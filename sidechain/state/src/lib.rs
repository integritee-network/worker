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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

mod error;
mod impls;

pub use error::*;
pub use impls::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
mod sgx_reexports {
	pub use thiserror_sgx as thiserror;
}

use codec::{Decode, Encode};
use itp_sgx_externalities::{SgxExternalitiesDiffType, SgxExternalitiesTrait, StateHash};
use its_primitives::{
	traits::Block as SidechainBlockTrait,
	types::{BlockHash, BlockNumber, Timestamp},
};
use sp_core::H256;
use sp_io::KillStorageResult;

/// Contains the necessary data to update the `SidechainDB` when importing a `SidechainBlock`.
#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct StateUpdate {
	/// state hash before the `state_update` was applied.
	state_hash_apriori: H256,
	/// state hash after the `state_update` was applied.
	state_hash_aposteriori: H256,
	/// state diff applied to state with hash `state_hash_apriori`
	/// leading to state with hash `state_hash_aposteriori`
	state_update: SgxExternalitiesDiffType,
}

impl StateUpdate {
	/// get state hash before the `state_update` was applied.
	pub fn state_hash_apriori(&self) -> H256 {
		self.state_hash_apriori
	}
	/// get state hash after the `state_update` was applied.
	pub fn state_hash_aposteriori(&self) -> H256 {
		self.state_hash_aposteriori
	}
	/// reference to the `state_update`
	pub fn state_update(&self) -> &SgxExternalitiesDiffType {
		&self.state_update
	}

	/// create new `StatePayload` instance.
	pub fn new(apriori: H256, aposteriori: H256, update: SgxExternalitiesDiffType) -> StateUpdate {
		StateUpdate {
			state_hash_apriori: apriori,
			state_hash_aposteriori: aposteriori,
			state_update: update,
		}
	}
}
/// Abstraction around the sidechain state.
pub trait SidechainState: Clone {
	type Externalities: SgxExternalitiesTrait + StateHash;

	type StateUpdate: Encode + Decode;

	/// Apply the state update to the state.
	///
	/// Does not guarantee state consistency in case of a failure.
	/// Caller is responsible for discarding corrupt/inconsistent state.
	fn apply_state_update(&mut self, state_payload: &Self::StateUpdate) -> Result<(), Error>;

	/// Get a storage value by its full name.
	fn get_with_name<V: Decode>(&self, module_prefix: &str, storage_prefix: &str) -> Option<V>;

	/// Set a storage value by its full name.
	fn set_with_name<V: Encode>(&mut self, module_prefix: &str, storage_prefix: &str, value: V);

	/// Clear a storage value by its full name.
	fn clear_with_name(&mut self, module_prefix: &str, storage_prefix: &str);

	/// Clear all storage values for the given prefix.
	fn clear_prefix_with_name(
		&mut self,
		module_prefix: &str,
		storage_prefix: &str,
	) -> KillStorageResult;

	/// Set a storage value by its storage hash.
	fn set(&mut self, key: &[u8], value: &[u8]);

	/// Clear a storage value by its storage hash.
	fn clear(&mut self, key: &[u8]);

	/// Clear a all storage values starting the given prefix.
	fn clear_sidechain_prefix(&mut self, prefix: &[u8]) -> KillStorageResult;
}

/// trait to set and get the last sidechain block of the sidechain state
pub trait LastBlockExt<SidechainBlock: SidechainBlockTrait> {
	/// get the last block of the sidechain state
	fn get_last_block(&self) -> Option<SidechainBlock>;

	/// set the last block of the sidechain state
	fn set_last_block(&mut self, block: &SidechainBlock);
}

impl<SidechainBlock: SidechainBlockTrait, E: SidechainState + SidechainSystemExt>
	LastBlockExt<SidechainBlock> for E
{
	fn get_last_block(&self) -> Option<SidechainBlock> {
		self.get_with_name("System", "LastBlock")
	}

	fn set_last_block(&mut self, block: &SidechainBlock) {
		self.set_last_block_hash(&block.hash());
		self.set_with_name("System", "LastBlock", block)
	}
}

/// System extension for the `SidechainDB`.
pub trait SidechainSystemExt {
	/// Get the last block number.
	fn get_block_number(&self) -> Option<BlockNumber>;

	/// Set the last block number.
	fn set_block_number(&mut self, number: &BlockNumber);

	/// Get the last block hash.
	fn get_last_block_hash(&self) -> Option<BlockHash>;

	/// Set the last block hash.
	fn set_last_block_hash(&mut self, hash: &BlockHash);

	/// Get the timestamp of.
	fn get_timestamp(&self) -> Option<Timestamp>;

	/// Set the timestamp.
	fn set_timestamp(&mut self, timestamp: &Timestamp);

	/// Resets the events.
	fn reset_events(&mut self);
}

impl<T: SidechainState> SidechainSystemExt for T {
	fn get_block_number(&self) -> Option<BlockNumber> {
		self.get_with_name("System", "Number")
	}

	fn set_block_number(&mut self, number: &BlockNumber) {
		self.set_with_name("System", "Number", number)
	}

	fn get_last_block_hash(&self) -> Option<BlockHash> {
		self.get_with_name("System", "LastHash")
	}

	fn set_last_block_hash(&mut self, hash: &BlockHash) {
		self.set_with_name("System", "LastHash", hash)
	}

	fn get_timestamp(&self) -> Option<Timestamp> {
		self.get_with_name("System", "Timestamp")
	}

	fn set_timestamp(&mut self, timestamp: &Timestamp) {
		self.set_with_name("System", "Timestamp", timestamp)
	}

	fn reset_events(&mut self) {
		self.clear_with_name("System", "Events");
		self.clear_with_name("System", "EventCount");
		self.clear_prefix_with_name("System", "EventTopics");
	}
}
