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

use crate::{
	error::{Error, Result},
	state::HandleState,
};
use ita_stf::{ShardIdentifier, State as StfState};
use itp_types::H256;
use sgx_externalities::SgxExternalitiesTrait;
use std::{
	collections::HashMap,
	string::ToString,
	sync::{SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard},
	vec::Vec,
};

/// Mock implementation for the `HandleState` trait
///
/// Uses an in-memory state, in a `HashMap`. To be used in unit tests.
pub struct HandleStateMock {
	state_map: RwLock<HashMap<ShardIdentifier, StfState>>,
}

impl Default for HandleStateMock {
	fn default() -> Self {
		HandleStateMock { state_map: Default::default() }
	}
}

impl HandleState for HandleStateMock {
	type WriteLockPayload = HashMap<ShardIdentifier, StfState>;

	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<StfState> {
		let maybe_state = self.state_map.read().unwrap().get(shard).map(|s| s.clone());

		return match maybe_state {
			// initialize with default state, if it doesn't exist yet
			None => {
				self.state_map.write().unwrap().insert(shard.clone(), StfState::default());

				self.state_map.read().unwrap().get(shard).map(|s| s.clone()).ok_or_else(|| {
					Error::Stf("state does not exist after inserting it".to_string())
				})
			},
			Some(s) => Ok(s),
		}
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)> {
		let initialized_state = self.load_initialized(shard)?;
		let write_lock = self.state_map.write().unwrap();
		Ok((write_lock, initialized_state))
	}

	fn write(
		&self,
		state: StfState,
		mut state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256> {
		state_lock.insert(shard.clone(), state);
		Ok(H256::default())
	}

	fn exists(&self, shard: &ShardIdentifier) -> bool {
		self.state_map.read().unwrap().get(shard).is_some()
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.state_map.read().unwrap().iter().map(|(k, _)| k.clone()).collect())
	}
}

// Since the mock itself has quite a bit of complexity, we also have tests for the mock
pub mod tests {

	use super::*;
	use codec::Encode;

	pub fn load_initialized_inserts_default_state() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();

		let loaded_state_result = state_handler.load_initialized(&shard);

		assert!(loaded_state_result.is_ok());
	}

	pub fn load_mutate_and_write_works() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();

		let (lock, mut state) = state_handler.load_for_mutation(&shard).unwrap();

		let (key, value) = ("my_key", "my_value");
		state.insert(key.encode(), value.encode());

		state_handler.write(state, lock, &shard).unwrap();

		let updated_state = state_handler.load_initialized(&shard).unwrap();

		let inserted_value =
			updated_state.get(key.encode().as_slice()).expect("value for key should exist");
		assert_eq!(*inserted_value, value.encode());
	}
}
