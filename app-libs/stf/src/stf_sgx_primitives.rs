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
#[cfg(feature = "sgx")]
use codec::{Decode, Encode};

use itp_types::H256;

pub mod types {
	#[cfg(feature = "sgx")]
	pub use sgx_runtime::{Balance, Index};
	#[cfg(feature = "sgx")]
	pub type AccountData = balances::AccountData<Balance>;
	#[cfg(feature = "sgx")]
	pub type AccountInfo = system::AccountInfo<Index, AccountData>;

	pub type StateType = sgx_externalities::SgxExternalitiesType;
	pub type State = sgx_externalities::SgxExternalities;
	pub type StateTypeDiff = sgx_externalities::SgxExternalitiesDiffType;
	pub use super::StatePayload;
	pub struct Stf;
}

use types::StateTypeDiff;

/// payload to be sent to peers for a state update
#[cfg_attr(not(feature = "std"), derive(Encode, Decode))] // given by externalities
#[derive(PartialEq, Eq, Clone, Debug)]
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
