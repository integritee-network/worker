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

use crate::{AccountId, Index};
use codec::{Decode, Encode};
use derive_more::Display;
use itp_types::H256;
use sgx_tstd as std;
use std::prelude::v1::*;

pub type StfResult<T> = Result<T, StfError>;

pub mod types {
	pub use sgx_runtime::{Balance, Index};
	pub type AccountData = balances::AccountData<Balance>;
	pub type AccountInfo = system::AccountInfo<Index, AccountData>;

	pub type StateType = sgx_externalities::SgxExternalitiesType;
	pub type State = sgx_externalities::SgxExternalities;
	pub type StateTypeDiff = sgx_externalities::SgxExternalitiesDiffType;
	pub use super::StatePayload;
	pub struct Stf;
}

use types::StateTypeDiff;

/// payload to be sent to peers for a state update
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
pub struct StatePayload {
	/// state hash before the `state_update` was applied.
	state_hash_apriori: H256,
	/// state hash after the `state_update` was applied.
	state_hash_aposteriori: H256,
	/// state diff applied to state with hash `state_hash_apriori`
	/// leading to state with hash `state_hash_aposteriori`
	state_update: StateTypeDiff,
}

impl StatePayload {
	/// get state hash before the `state_update` was applied.
	pub fn state_hash_apriori(&self) -> H256 {
		self.state_hash_apriori
	}
	/// get state hash after the `state_update` was applied.
	pub fn state_hash_aposteriori(&self) -> H256 {
		self.state_hash_aposteriori
	}
	/// reference to the `state_update`
	pub fn state_update(&self) -> &StateTypeDiff {
		&self.state_update
	}

	/// create new `StatePayload` instance.
	pub fn new(apriori: H256, aposteriori: H256, update: StateTypeDiff) -> StatePayload {
		StatePayload {
			state_hash_apriori: apriori,
			state_hash_aposteriori: aposteriori,
			state_update: update,
		}
	}
}

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
