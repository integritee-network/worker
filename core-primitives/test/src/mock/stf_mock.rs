/*
	Copyright 2021 Integritee AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/
use codec::{Decode, Encode};
use itp_stf_primitives::{
	traits::{
		GetterAuthorization, PoolTransactionValidation, TrustedCallSigning, TrustedCallVerification,
	},
	types::{KeyPair, TrustedOperation},
};
use itp_types::{AccountId, Balance, Index, ShardIdentifier, Signature};
use sp_runtime::transaction_validity::{
	TransactionValidityError, UnknownTransaction, ValidTransaction,
};

type TrustedOperationMock = TrustedOperation<TrustedCallSignedMock, GetterMock>;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCallMock {
	balance_transfer(AccountId, AccountId, Balance),
}

impl TrustedCallMock {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::balance_transfer(sender_account, ..) => sender_account,
		}
	}
}

impl TrustedCallSigning<TrustedCallSignedMock> for TrustedCallMock {
	fn sign(
		&self,
		pair: &KeyPair,
		nonce: Index,
		mrenclave: &[u8; 32],
		shard: &ShardIdentifier,
	) -> TrustedCallSignedMock {
		let mut payload = self.encode();
		payload.append(&mut nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());

		TrustedCallSignedMock {
			call: self.clone(),
			nonce,
			signature: pair.sign(payload.as_slice()),
		}
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSignedMock {
	pub call: TrustedCallMock,
	pub nonce: Index,
	pub signature: Signature,
}

impl TrustedCallSignedMock {
	pub fn new(call: TrustedCallMock, nonce: Index, signature: Signature) -> Self {
		TrustedCallSignedMock { call, nonce, signature }
	}

	pub fn into_trusted_operation(
		self,
		direct: bool,
	) -> TrustedOperation<TrustedCallSignedMock, GetterMock> {
		match direct {
			true => TrustedOperation::direct_call(self),
			false => TrustedOperation::indirect_call(self),
		}
	}
}

impl TrustedCallVerification for TrustedCallSignedMock {
	fn sender_account(&self) -> &AccountId {
		&self.call.sender_account()
	}

	fn nonce(&self) -> Index {
		self.nonce
	}

	fn verify_signature(&self, _mrenclave: &[u8; 32], _shard: &ShardIdentifier) -> bool {
		true
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum GetterMock {
	public(u8),
	trusted(u8),
}

impl PoolTransactionValidation for GetterMock {
	fn validate(&self) -> Result<ValidTransaction, TransactionValidityError> {
		Err(TransactionValidityError::Unknown(UnknownTransaction::CannotLookup))
	}
}

impl GetterAuthorization for GetterMock {
	fn is_authorized(&self) -> bool {
		match self {
			Self::trusted(_) => false,
			Self::public(_) => true,
		}
	}
}
