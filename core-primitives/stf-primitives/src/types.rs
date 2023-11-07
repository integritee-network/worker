/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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
extern crate alloc;
use crate::traits::{PoolTransactionValidation, TrustedCallVerification};
use alloc::boxed::Box;
use codec::{Compact, Decode, Encode};
use core::{fmt::Debug};
use sp_core::{blake2_256, crypto::AccountId32, ed25519, sr25519, Pair, H256};
use sp_runtime::{
	traits::Verify,
	transaction_validity::{TransactionValidityError, ValidTransaction},
	MultiSignature,
};
use sp_std::{vec, vec::Vec};
pub type Signature = MultiSignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = AccountId32;
pub type Hash = H256;
pub type BalanceTransferFn = ([u8; 2], AccountId, Compact<u128>);
pub type ShardIdentifier = H256;

#[derive(Clone)]
pub enum KeyPair {
	Sr25519(Box<sr25519::Pair>),
	Ed25519(Box<ed25519::Pair>),
}

impl KeyPair {
	pub fn sign(&self, payload: &[u8]) -> Signature {
		match self {
			Self::Sr25519(pair) => pair.sign(payload).into(),
			Self::Ed25519(pair) => pair.sign(payload).into(),
		}
	}
}

impl From<ed25519::Pair> for KeyPair {
	fn from(x: ed25519::Pair) -> Self {
		KeyPair::Ed25519(Box::new(x))
	}
}

impl From<sr25519::Pair> for KeyPair {
	fn from(x: sr25519::Pair) -> Self {
		KeyPair::Sr25519(Box::new(x))
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedOperation<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	indirect_call(TCS),
	direct_call(TCS),
	get(G),
}

impl<TCS, G> From<G> for TrustedOperation<TCS, G>
where
	TCS: Encode + Debug,
	G: Encode + Debug,
{
	fn from(item: G) -> Self {
		TrustedOperation::get(item)
	}
}

// impl<TCS, G> itp_hashing::Hash<H256> for TrustedOperation<TCS, G>
// where
// 	TCS: Encode,
// 	G: Encode,
// {
// 	fn hash(&self) -> H256 {
// 		blake2_256(&self.encode()).into()
// 	}
// }

impl<TCS, G> TrustedOperation<TCS, G>
where
	TCS: TrustedCallVerification + Encode + Debug,
	G: Encode + Debug,
{
	pub fn to_call(&self) -> Option<&TCS> {
		match self {
			TrustedOperation::direct_call(c) => Some(c),
			TrustedOperation::indirect_call(c) => Some(c),
			_ => None,
		}
	}

	pub fn signed_caller_account(&self) -> Option<&AccountId> {
		match self {
			TrustedOperation::direct_call(c) => Some(c.sender_account()),
			TrustedOperation::indirect_call(c) => Some(c.sender_account()),
			_ => None,
		}
	}

	fn validate_trusted_call(trusted_call_signed: &TCS) -> ValidTransaction {
		let from = trusted_call_signed.sender_account();
		let requires = vec![];
		let provides = vec![(from, trusted_call_signed.nonce()).encode()];

		ValidTransaction { priority: 1 << 20, requires, provides, longevity: 64, propagate: true }
	}

	pub fn hash(&self) -> H256 {
		blake2_256(&self.encode()).into()
	}
}

impl<TCS, G> PoolTransactionValidation for TrustedOperation<TCS, G>
where
	TCS: TrustedCallVerification + Encode + Debug,
	G: Encode + PoolTransactionValidation + Debug,
{
	fn validate(&self) -> Result<ValidTransaction, TransactionValidityError> {
		match self {
			TrustedOperation::direct_call(trusted_call_signed) =>
				Ok(Self::validate_trusted_call(trusted_call_signed)),
			TrustedOperation::indirect_call(trusted_call_signed) =>
				Ok(Self::validate_trusted_call(trusted_call_signed)),
			TrustedOperation::get(getter) => getter.validate(),
		}
	}
}

/// Trusted operation Or hash
///
/// Allows to refer to trusted calls either by its raw representation or its hash.
#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub enum TrustedOperationOrHash<TCS, G>
where
	TCS: Encode + Debug + Send + Sync,
	G: Encode + Debug + Send + Sync,
{
	/// The hash of the call.
	Hash(H256),
	/// Raw extrinsic bytes.
	OperationEncoded(Vec<u8>),
	/// Raw extrinsic
	Operation(Box<TrustedOperation<TCS, G>>),
}

impl<TCS, G> TrustedOperationOrHash<TCS, G>
where
	TCS: Encode + Debug + Send + Sync,
	G: Encode + Debug + Send + Sync,
{
	pub fn from_top(top: TrustedOperation<TCS, G>) -> Self {
		TrustedOperationOrHash::Operation(Box::new(top))
	}
}

/// Payload to be sent to peers for a state update.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct StatePayload<StateUpdate: Encode> {
	/// State hash before the `state_update` was applied.
	state_hash_apriori: H256,
	/// State hash after the `state_update` was applied.
	state_hash_aposteriori: H256,
	/// State diff applied to state with hash `state_hash_apriori`
	/// leading to state with hash `state_hash_aposteriori`.
	state_update: StateUpdate,
}

impl<StateUpdate: Encode> StatePayload<StateUpdate> {
	/// Get state hash before the `state_update` was applied.
	pub fn state_hash_apriori(&self) -> H256 {
		self.state_hash_apriori
	}
	/// Get state hash after the `state_update` was applied.
	pub fn state_hash_aposteriori(&self) -> H256 {
		self.state_hash_aposteriori
	}
	/// Reference to the `state_update`.
	pub fn state_update(&self) -> &StateUpdate {
		&self.state_update
	}

	/// Create new `StatePayload` instance.
	pub fn new(apriori: H256, aposteriori: H256, update: StateUpdate) -> Self {
		Self {
			state_hash_apriori: apriori,
			state_hash_aposteriori: aposteriori,
			state_update: update,
		}
	}
}
