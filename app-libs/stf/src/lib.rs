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

/////////////////////////////////////////////////////////////////////////////
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

extern crate alloc;

use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
pub use my_node_runtime::{Balance, Index};
#[cfg(feature = "sgx")]
pub use sgx_runtime::{Balance, Index};

use codec::{Compact, Decode, Encode};
use derive_more::Display;
use sp_core::{crypto::AccountId32, ed25519, sr25519, Pair, H256};
use sp_runtime::{traits::Verify, MultiSignature};
use std::string::String;
use support::{traits::Get, BoundedVec};

pub type Signature = MultiSignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = AccountId32;
pub type Hash = sp_core::H256;
pub type BalanceTransferFn = ([u8; 2], AccountId, Compact<u128>);

pub const MAX_PLAYERS_ALLOWED: u32 = 2;
pub struct MaxPlayers;
impl Get<u32> for MaxPlayers {
	fn get() -> u32 {
		MAX_PLAYERS_ALLOWED
	}
}

pub type SgxBoardId = u32;
pub type SgxGameState = pallet_ajuna_board::dot4gravity::GameState<AccountId>;
pub type SgxGameTurn = pallet_ajuna_board::dot4gravity::Turn;
pub type Coordinates = pallet_ajuna_board::dot4gravity::Coordinates;
pub type Side = pallet_ajuna_board::dot4gravity::Side;

pub type SgxGameBoardStruct =
	pallet_ajuna_board::BoardGame<SgxBoardId, SgxGameState, BoundedVec<AccountId, MaxPlayers>>;

pub struct SgxWinningBoard {
	pub winner: AccountId,
	pub board_id: SgxBoardId,
}

pub type ShardIdentifier = H256;

pub type StfResult<T> = Result<T, StfError>;

#[derive(Debug, Display, PartialEq, Eq)]
pub enum StfError {
	#[display(fmt = "Insufficient privileges {:?}, are you sure you are root?", _0)]
	MissingPrivileges(AccountId),
	#[display(fmt = "Error dispatching runtime call. {:?}", _0)]
	Dispatch(String),
	#[display(fmt = "Not enough funds to perform operation")]
	MissingFunds,
	#[display(fmt = "Account does not exist {:?}", _0)]
	InexistentAccount(AccountId),
	#[display(fmt = "Invalid Nonce {:?}", _0)]
	InvalidNonce(Index),
	StorageHashMismatch,
	InvalidStorageDiff,
}

#[derive(Clone)]
pub enum KeyPair {
	Sr25519(sr25519::Pair),
	Ed25519(ed25519::Pair),
}

impl KeyPair {
	fn sign(&self, payload: &[u8]) -> Signature {
		match self {
			Self::Sr25519(pair) => pair.sign(payload).into(),
			Self::Ed25519(pair) => pair.sign(payload).into(),
		}
	}
}

impl From<ed25519::Pair> for KeyPair {
	fn from(x: ed25519::Pair) -> Self {
		KeyPair::Ed25519(x)
	}
}

impl From<sr25519::Pair> for KeyPair {
	fn from(x: sr25519::Pair) -> Self {
		KeyPair::Sr25519(x)
	}
}

pub mod hash;
pub mod helpers;
pub mod stf_sgx_primitives;

#[cfg(feature = "sgx")]
pub mod stf_sgx;
#[cfg(all(feature = "test", feature = "sgx"))]
pub mod test_genesis;

pub use stf_sgx_primitives::types::*;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedOperation {
	indirect_call(TrustedCallSigned),
	direct_call(TrustedCallSigned),
	get(Getter),
}

impl From<TrustedCallSigned> for TrustedOperation {
	fn from(item: TrustedCallSigned) -> Self {
		TrustedOperation::indirect_call(item)
	}
}

impl From<Getter> for TrustedOperation {
	fn from(item: Getter) -> Self {
		TrustedOperation::get(item)
	}
}

impl From<TrustedGetterSigned> for TrustedOperation {
	fn from(item: TrustedGetterSigned) -> Self {
		TrustedOperation::get(item.into())
	}
}

impl From<PublicGetter> for TrustedOperation {
	fn from(item: PublicGetter) -> Self {
		TrustedOperation::get(item.into())
	}
}

impl TrustedOperation {
	pub fn to_call(&self) -> Option<&TrustedCallSigned> {
		match self {
			TrustedOperation::direct_call(c) => Some(c),
			TrustedOperation::indirect_call(c) => Some(c),
			_ => None,
		}
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Getter {
	public(PublicGetter),
	trusted(TrustedGetterSigned),
}

impl From<PublicGetter> for Getter {
	fn from(item: PublicGetter) -> Self {
		Getter::public(item)
	}
}

impl From<TrustedGetterSigned> for Getter {
	fn from(item: TrustedGetterSigned) -> Self {
		Getter::trusted(item)
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum PublicGetter {
	some_value,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
	balance_set_balance(AccountId, AccountId, Balance, Balance),
	balance_transfer(AccountId, AccountId, Balance),
	balance_unshield(AccountId, AccountId, Balance, ShardIdentifier), // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
	balance_shield(AccountId, AccountId, Balance), // (Root, AccountIncognito, Amount)
	board_new_game(AccountId, SgxBoardId, BTreeSet<AccountId>),
	board_play_turn(AccountId, SgxGameTurn),
	board_finish_game(AccountId, SgxBoardId),
}

impl TrustedCall {
	pub fn account(&self) -> &AccountId {
		match self {
			TrustedCall::balance_set_balance(account, _, _, _) => account,
			TrustedCall::balance_transfer(account, _, _) => account,
			TrustedCall::balance_unshield(account, _, _, _) => account,
			TrustedCall::balance_shield(account, _, _) => account,
			TrustedCall::board_new_game(account, _, _) => account,
			TrustedCall::board_play_turn(account, _) => account,
			TrustedCall::board_finish_game(account, _) => account,
		}
	}

	pub fn sign(
		&self,
		pair: &KeyPair,
		nonce: Index,
		mrenclave: &[u8; 32],
		shard: &ShardIdentifier,
	) -> TrustedCallSigned {
		let mut payload = self.encode();
		payload.append(&mut nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());

		TrustedCallSigned { call: self.clone(), nonce, signature: pair.sign(payload.as_slice()) }
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedGetter {
	free_balance(AccountId),
	reserved_balance(AccountId),
	nonce(AccountId),
	board(AccountId),
}

impl TrustedGetter {
	pub fn account(&self) -> &AccountId {
		match self {
			TrustedGetter::free_balance(account) => account,
			TrustedGetter::reserved_balance(account) => account,
			TrustedGetter::nonce(account) => account,
			TrustedGetter::board(account) => account,
		}
	}

	pub fn sign(&self, pair: &KeyPair) -> TrustedGetterSigned {
		let signature = pair.sign(self.encode().as_slice());
		TrustedGetterSigned { getter: self.clone(), signature }
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedGetterSigned {
	pub getter: TrustedGetter,
	pub signature: Signature,
}

impl TrustedGetterSigned {
	pub fn new(getter: TrustedGetter, signature: Signature) -> Self {
		TrustedGetterSigned { getter, signature }
	}

	pub fn verify_signature(&self) -> bool {
		self.signature.verify(self.getter.encode().as_slice(), self.getter.account())
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSigned {
	pub call: TrustedCall,
	pub nonce: Index,
	pub signature: Signature,
}

impl TrustedCallSigned {
	pub fn new(call: TrustedCall, nonce: Index, signature: Signature) -> Self {
		TrustedCallSigned { call, nonce, signature }
	}

	pub fn verify_signature(&self, mrenclave: &[u8; 32], shard: &ShardIdentifier) -> bool {
		let mut payload = self.call.encode();
		payload.append(&mut self.nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());
		self.signature.verify(payload.as_slice(), self.call.account())
	}

	pub fn into_trusted_operation(self, direct: bool) -> TrustedOperation {
		match direct {
			true => TrustedOperation::direct_call(self),
			false => TrustedOperation::indirect_call(self),
		}
	}
}

// TODO: #91 signed return value
/*
pub struct TrustedReturnValue<T> {
	pub value: T,
	pub signer: AccountId
}

impl TrustedReturnValue
*/

#[cfg(test)]
mod tests {
	use super::*;
	use sp_keyring::AccountKeyring;

	#[test]
	fn verify_signature_works() {
		let nonce = 21;
		let mrenclave = [0u8; 32];
		let shard = ShardIdentifier::default();

		let call = TrustedCall::balance_set_balance(
			AccountKeyring::Alice.public().into(),
			AccountKeyring::Alice.public().into(),
			42,
			42,
		);
		let signed_call =
			call.sign(&KeyPair::Sr25519(AccountKeyring::Alice.pair()), nonce, &mrenclave, &shard);

		assert!(signed_call.verify_signature(&mrenclave, &shard));
	}
}
