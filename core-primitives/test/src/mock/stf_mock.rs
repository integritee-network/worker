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
use alloc::sync::Arc;
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_node_api::metadata::metadata_mocks::NodeMetadataMock;
use itp_node_api_metadata_provider::NodeMetadataRepository;
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesDiffType};
use itp_stf_interface::{ExecuteCall, StateCallInterface, UpdateState};
use itp_stf_primitives::{
	traits::{
		GetterAuthorization, PoolTransactionValidation, TrustedCallSigning, TrustedCallVerification,
	},
	types::{KeyPair, TrustedOperation},
};
use itp_types::{
	parentchain::ParentchainId, AccountId, Balance, Index, OpaqueCall, ShardIdentifier, Signature,
};
use sp_runtime::transaction_validity::{
	TransactionValidityError, UnknownTransaction, ValidTransaction,
};
use sp_std::{vec, vec::Vec};

// a few dummy types
type NodeMetadataRepositoryMock = NodeMetadataRepository<NodeMetadataMock>;

#[derive(Debug, PartialEq, Eq)]
pub enum StfMockError {
	Dummy,
}
#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct StfMock {
	state: SgxExternalities,
}

impl UpdateState<SgxExternalities, SgxExternalitiesDiffType> for StfMock {
	fn apply_state_diff(_state: &mut SgxExternalities, _map_update: SgxExternalitiesDiffType) {}

	fn storage_hashes_to_update_on_block(_parentchain_id: &ParentchainId) -> Vec<Vec<u8>> {
		vec![]
	}
}

impl StateCallInterface<TrustedCallSignedMock, SgxExternalities, NodeMetadataRepositoryMock>
	for StfMock
{
	type Error = StfMockError;

	fn execute_call(
		_state: &mut SgxExternalities,
		_call: TrustedCallSignedMock,
		_calls: &mut Vec<OpaqueCall>,
		_node_metadata_repo: Arc<NodeMetadataRepositoryMock>,
	) -> Result<(), Self::Error> {
		Ok(())
	}
}

pub type TrustedOperationMock = TrustedOperation<TrustedCallSignedMock, GetterMock>;

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

impl ExecuteCall<NodeMetadataRepositoryMock> for TrustedCallSignedMock {
	type Error = StfMockError;

	fn execute(
		self,
		_calls: &mut Vec<OpaqueCall>,
		_node_metadata_repo: Arc<NodeMetadataRepositoryMock>,
	) -> Result<(), Self::Error> {
		Ok(())
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
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
