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
use std::sync::{SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard};

#[cfg(feature = "std")]
use std::sync::{RwLock, RwLockWriteGuard};

use codec::Encode;
use ita_stf::State as StfState;
use itp_stf_state_handler::{
	error::{Error, Result},
	handle_state::HandleState,
	query_shard_state::QueryShardState,
};
use itp_types::{ShardIdentifier, H256};
use sp_core::blake2_256;
use std::{collections::HashMap, format, vec::Vec};

/// Mock implementation for the `HandleState` trait.
///
/// Uses an in-memory state, in a `HashMap`. To be used in unit tests.
#[derive(Default)]
pub struct HandleStateMock {
	state_map: RwLock<HashMap<ShardIdentifier, StfState>>,
}

impl HandleStateMock {
	pub fn from_shard(shard: ShardIdentifier) -> Result<Self> {
		let state_handler = HandleStateMock { state_map: Default::default() };
		state_handler.initialize_shard(shard)?;
		Ok(state_handler)
	}
}

impl HandleState for HandleStateMock {
	type WriteLockPayload = HashMap<ShardIdentifier, StfState>;
	type StateT = StfState;
	type HashType = H256;

	fn initialize_shard(&self, shard: ShardIdentifier) -> Result<Self::HashType> {
		let maybe_state = self.state_map.read().unwrap().get(&shard).cloned();

		return match maybe_state {
			// Initialize with default state, if it doesn't exist yet.
			None => {
				let state = StfState::default();
				let state_hash = state.using_encoded(blake2_256).into();
				self.state_map.write().unwrap().insert(shard, state);
				Ok(state_hash)
			},
			Some(s) => Ok(s.using_encoded(blake2_256).into()),
		}
	}

	fn load(&self, shard: &ShardIdentifier) -> Result<StfState> {
		self.state_map
			.read()
			.unwrap()
			.get(shard)
			.cloned()
			.ok_or_else(|| Error::Other(format!("shard is not initialized {:?}", shard).into()))
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)> {
		let initialized_state = self.load(shard)?;
		let write_lock = self.state_map.write().unwrap();
		Ok((write_lock, initialized_state))
	}

	fn write_after_mutation(
		&self,
		state: StfState,
		mut state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<Self::HashType> {
		state_lock.insert(*shard, state.clone());
		Ok(state.using_encoded(blake2_256).into())
	}

	fn reset(&self, state: Self::StateT, shard: &ShardIdentifier) -> Result<Self::HashType> {
		let write_lock = self.state_map.write().unwrap();
		self.write_after_mutation(state, write_lock, shard)
	}
}

impl QueryShardState for HandleStateMock {
	fn shard_exists(&self, shard: &ShardIdentifier) -> Result<bool> {
		let state_map_lock = self.state_map.read().map_err(|_| Error::LockPoisoning)?;
		Ok(state_map_lock.get(shard).is_some())
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.state_map.read().unwrap().iter().map(|(k, _)| *k).collect())
	}
}

// Since the mock itself has quite a bit of complexity, we also have tests for the mock.
#[cfg(feature = "sgx")]
pub mod tests {

	use super::*;
	use codec::{Decode, Encode};
	use ita_stf::Stf;
	use itp_sgx_externalities::{SgxExternalitiesTrait, SgxExternalitiesType};
	use itp_types::ShardIdentifier;
	use sp_core::{blake2_256, crypto::AccountId32};

	pub fn initialized_shards_list_is_empty() {
		let state_handler = HandleStateMock::default();
		assert!(state_handler.list_shards().unwrap().is_empty());
	}

	pub fn shard_exists_after_inserting() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();
		state_handler.initialize_shard(shard).unwrap();

		assert!(state_handler.load(&shard).is_ok());
		assert!(state_handler.shard_exists(&shard).unwrap());
	}

	pub fn initialize_creates_default_state() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();
		state_handler.initialize_shard(shard).unwrap();

		let loaded_state_result = state_handler.load(&shard);

		assert!(loaded_state_result.is_ok());
	}

	pub fn load_mutate_and_write_works() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();
		state_handler.initialize_shard(shard).unwrap();

		let (lock, mut state) = state_handler.load_for_mutation(&shard).unwrap();

		let (key, value) = ("my_key", "my_value");
		state.insert(key.encode(), value.encode());

		state_handler.write_after_mutation(state, lock, &shard).unwrap();

		let updated_state = state_handler.load(&shard).unwrap();

		let inserted_value =
			updated_state.get(key.encode().as_slice()).expect("value for key should exist");
		assert_eq!(*inserted_value, value.encode());
	}

	pub fn ensure_subsequent_state_loads_have_same_hash() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();
		state_handler.initialize_shard(shard).unwrap();

		let (lock, _) = state_handler.load_for_mutation(&shard).unwrap();
		let initial_state = Stf::init_state(AccountId32::new([0u8; 32]));
		let state_hash_before_execution = hash_of(&initial_state.state);
		state_handler.write_after_mutation(initial_state, lock, &shard).unwrap();

		let state_loaded = state_handler.load(&shard).unwrap();
		let loaded_state_hash = hash_of(&state_loaded.state);

		assert_eq!(state_hash_before_execution, loaded_state_hash);
	}

	pub fn ensure_encode_and_encrypt_does_not_affect_state_hash() {
		let state = Stf::init_state(AccountId32::new([0u8; 32]));
		let state_hash_before_execution = hash_of(&state.state);

		let encoded_state = state.state.encode();
		let decoded_state: SgxExternalitiesType = decode(encoded_state);

		let decoded_state_hash = hash_of(&decoded_state);

		assert_eq!(state_hash_before_execution, decoded_state_hash);
	}

	fn hash_of<T: Encode>(encodable: &T) -> H256 {
		encodable.using_encoded(blake2_256).into()
	}

	fn decode<T: Decode>(encoded: Vec<u8>) -> T {
		T::decode(&mut encoded.as_slice()).unwrap()
	}
}
