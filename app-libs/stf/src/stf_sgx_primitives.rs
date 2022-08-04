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

use super::{Balance, Index};
use codec::{Decode, Encode};
use itp_types::H256;
#[cfg(all(not(feature = "sgx"), feature = "std"))]
use sp_runtime::traits::BlakeTwo256;

pub mod types {
	use super::*;

	pub type AccountData = balances::AccountData<Balance>;
	pub type AccountInfo = system::AccountInfo<Index, AccountData>;
	// FIXME after fixing sgx-runtime issue #37
	#[cfg(all(not(feature = "std"), feature = "sgx"))]
	pub type ParentchainHeader = ita_sgx_runtime::Header;
	#[cfg(all(not(feature = "sgx"), feature = "std"))]
	pub type BlockNumber = u32;
	#[cfg(all(not(feature = "std"), feature = "sgx"))]
	pub type BlockNumber = ita_sgx_runtime::BlockNumber;
	#[cfg(all(not(feature = "sgx"), feature = "std"))]
	pub type ParentchainHeader = sp_runtime::generic::Header<BlockNumber, BlakeTwo256>;

	pub type StateType = itp_sgx_externalities::SgxExternalitiesType;
	pub type State = itp_sgx_externalities::SgxExternalities;
	pub type StateTypeDiff = itp_sgx_externalities::SgxExternalitiesDiffType;
	pub use super::StatePayload;
	pub struct Stf;
}

use types::StateTypeDiff;

/// Payload to be sent to peers for a state update.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct StatePayload {
	/// State hash before the `state_update` was applied.
	state_hash_apriori: H256,
	/// State hash after the `state_update` was applied.
	state_hash_aposteriori: H256,
	/// State diff applied to state with hash `state_hash_apriori`
	/// leading to state with hash `state_hash_aposteriori`.
	state_update: StateTypeDiff,
}

impl StatePayload {
	/// Get state hash before the `state_update` was applied.
	pub fn state_hash_apriori(&self) -> H256 {
		self.state_hash_apriori
	}
	/// Get state hash after the `state_update` was applied.
	pub fn state_hash_aposteriori(&self) -> H256 {
		self.state_hash_aposteriori
	}
	/// Reference to the `state_update`.
	pub fn state_update(&self) -> &StateTypeDiff {
		&self.state_update
	}

	/// Create new `StatePayload` instance.
	pub fn new(apriori: H256, aposteriori: H256, update: StateTypeDiff) -> StatePayload {
		StatePayload {
			state_hash_apriori: apriori,
			state_hash_aposteriori: aposteriori,
			state_update: update,
		}
	}
}
