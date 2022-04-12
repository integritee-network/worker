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
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::{Error, Result},
	file_io::StateFileIo,
	state_snapshot_primitives::StateId,
};
use codec::Encode;
use itp_types::ShardIdentifier;
use std::{collections::HashMap, hash::Hasher as HasherTrait, vec::Vec};

type StateHash = u64;
type ShardDirectory<State> = HashMap<StateId, (StateHash, State)>;
type ShardsRootDirectory<State> = HashMap<ShardIdentifier, ShardDirectory<State>>;

/// State file I/O using (unencrypted) in-memory representation of the state files.
/// Uses u64 hash type. Can be used as mock for testing.
#[derive(Default)]
pub struct InMemoryStateFileIo<State, Hasher>
where
	State: Clone + Default + Encode,
	Hasher: HasherTrait + Clone + Default,
{
	emulated_shard_directory: RwLock<ShardsRootDirectory<State>>,
	hasher: Hasher,
}

impl<State, Hasher> InMemoryStateFileIo<State, Hasher>
where
	State: Clone + Default + Encode,
	Hasher: HasherTrait + Clone + Default,
{
	#[allow(unused)]
	pub fn new(hash_function: Hasher, shards: &[ShardIdentifier]) -> Self {
		let shard_hash_map: HashMap<_, _> =
			shards.iter().map(|s| (*s, ShardDirectory::<State>::default())).collect();

		InMemoryStateFileIo {
			emulated_shard_directory: RwLock::new(shard_hash_map),
			hasher: hash_function,
		}
	}

	#[cfg(test)]
	pub fn get_states_for_shard(
		&self,
		shard_identifier: &ShardIdentifier,
	) -> Result<ShardDirectory<State>> {
		let files_lock = self.emulated_shard_directory.read().map_err(|_| Error::LockPoisoning)?;
		files_lock
			.get(shard_identifier)
			.cloned()
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))
	}

	fn compute_state_hash(&self, state: &State) -> StateHash {
		let encoded_state = state.encode();
		let mut hasher = self.hasher.clone();
		hasher.write(encoded_state.as_slice());
		hasher.finish()
	}

	fn default_states_map(&self, state_id: StateId) -> ShardDirectory<State> {
		self.initialize_states_map(state_id, State::default())
	}

	fn initialize_states_map(&self, state_id: StateId, state: State) -> ShardDirectory<State> {
		HashMap::from([(state_id, self.generate_state_entry(state))])
	}

	fn generate_default_state_entry(&self) -> (StateHash, State) {
		self.generate_state_entry(State::default())
	}

	fn generate_state_entry(&self, state: State) -> (StateHash, State) {
		let state_hash = self.compute_state_hash(&state);
		(state_hash, state)
	}
}

impl<State, Hasher> StateFileIo for InMemoryStateFileIo<State, Hasher>
where
	State: Clone + Default + Encode,
	Hasher: HasherTrait + Clone + Default,
{
	type StateType = State;
	type HashType = StateHash;

	fn load(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::StateType> {
		let directory_lock =
			self.emulated_shard_directory.read().map_err(|_| Error::LockPoisoning)?;
		let states_for_shard = directory_lock
			.get(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))?;
		states_for_shard
			.get(&state_id)
			.map(|(_, s)| -> State { s.clone() })
			.ok_or(Error::InvalidStateId(state_id))
	}

	fn compute_hash(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::HashType> {
		let state = self.load(shard_identifier, state_id)?;
		Ok(self.compute_state_hash(&state))
	}

	fn create_initialized(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::HashType> {
		let mut directory_lock =
			self.emulated_shard_directory.write().map_err(|_| Error::LockPoisoning)?;
		let states_for_shard = directory_lock
			.entry(*shard_identifier)
			.or_insert_with(|| self.default_states_map(state_id));
		let state_entry = states_for_shard
			.entry(state_id)
			.or_insert_with(|| self.generate_state_entry(State::default()));
		Ok(state_entry.0)
	}

	fn write(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
		state: Self::StateType,
	) -> Result<Self::HashType> {
		let mut directory_lock =
			self.emulated_shard_directory.write().map_err(|_| Error::LockPoisoning)?;

		let states_for_shard = directory_lock
			.entry(*shard_identifier)
			.or_insert_with(|| self.default_states_map(state_id));

		let state_hash = self.compute_state_hash(&state);
		*states_for_shard
			.entry(state_id)
			.or_insert_with(|| self.generate_default_state_entry()) = (state_hash, state);

		Ok(state_hash)
	}

	fn remove(&self, shard_identifier: &ShardIdentifier, state_id: StateId) -> Result<()> {
		let mut directory_lock =
			self.emulated_shard_directory.write().map_err(|_| Error::LockPoisoning)?;

		let states_for_shard = directory_lock
			.get_mut(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))?;

		states_for_shard
			.remove(&state_id)
			.ok_or(Error::InvalidStateId(state_id))
			.map(|_| {})
	}

	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
		let directory_lock = self.emulated_shard_directory.read().unwrap();
		directory_lock.contains_key(shard_identifier)
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		let directory_lock =
			self.emulated_shard_directory.read().map_err(|_| Error::LockPoisoning)?;
		Ok(directory_lock.keys().copied().collect())
	}

	fn list_state_ids_for_shard(&self, shard_identifier: &ShardIdentifier) -> Result<Vec<StateId>> {
		let directory_lock =
			self.emulated_shard_directory.read().map_err(|_| Error::LockPoisoning)?;
		let shard_directory = directory_lock
			.get(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))?;
		Ok(shard_directory.keys().cloned().collect())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::{assert_matches::assert_matches, collections::hash_map::DefaultHasher};

	type TestState = u64;
	type TestStateFileIo = InMemoryStateFileIo<TestState, DefaultHasher>;

	#[test]
	fn shard_directory_is_empty_after_initialization() {
		let state_file_io = create_empty_in_memory_state_file_io();
		assert!(state_file_io.list_shards().unwrap().is_empty());
	}

	#[test]
	fn load_on_empty_directory_and_shard_returns_error() {
		let state_file_io = create_empty_in_memory_state_file_io();

		assert_matches!(
			state_file_io.load(&ShardIdentifier::random(), 1234),
			Err(Error::InvalidShard(_))
		);
	}

	#[test]
	fn initialize_with_shard_creates_empty_directory() {
		let shard = ShardIdentifier::from([2u8; 32]);
		let state_file_io = create_in_memory_state_file_io(&[shard]);

		assert!(state_file_io.list_state_ids_for_shard(&shard).unwrap().is_empty());
		assert!(state_file_io
			.list_state_ids_for_shard(&ShardIdentifier::from([3u8; 32]))
			.is_err());
	}

	#[test]
	fn load_when_state_does_not_exist_returns_error() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let _ = state_file_io.create_initialized(&shard_id, 1234).unwrap();

		assert_matches!(state_file_io.load(&shard_id, 12345), Err(Error::InvalidStateId(12345)));
	}

	#[test]
	fn create_initialized_when_shard_already_exists_works() {
		let shard = ShardIdentifier::random();
		let state_file_io = create_in_memory_state_file_io(&[shard]);

		assert!(state_file_io.create_initialized(&shard, 1245).is_ok());
	}

	#[test]
	fn create_initialized_adds_default_state() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let state_id = 31081984u128;
		let state_hash = state_file_io.create_initialized(&shard_id, state_id).unwrap();

		assert_eq!(1, state_file_io.list_shards().unwrap().len());
		assert_eq!(TestState::default(), state_file_io.load(&shard_id, state_id).unwrap());
		assert_eq!(1, state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len());

		assert_entry(&state_file_io, &shard_id, state_id, &StateHash::default(), &state_hash);
	}

	#[test]
	fn write_works_when_no_previous_shard_or_file_exists() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let state_id = 23u128;
		let test_state = 42u64;

		let state_hash = state_file_io.write(&shard_id, state_id, test_state).unwrap();

		assert_eq!(1, state_file_io.list_shards().unwrap().len());
		assert_eq!(test_state, state_file_io.load(&shard_id, state_id).unwrap());
		assert_eq!(1, state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len());
		assert_entry(&state_file_io, &shard_id, state_id, &test_state, &state_hash);
	}

	#[test]
	fn write_overwrites_existing_state() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let state_id = 123456u128;
		let _ = state_file_io.create_initialized(&shard_id, state_id).unwrap();

		let test_state = 4256u64;
		let state_hash = state_file_io.write(&shard_id, state_id, test_state).unwrap();

		assert_eq!(1, state_file_io.list_shards().unwrap().len());
		assert_eq!(test_state, state_file_io.load(&shard_id, state_id).unwrap());
		assert_eq!(1, state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len());
		assert_entry(&state_file_io, &shard_id, state_id, &test_state, &state_hash);
	}

	#[test]
	fn remove_files_works() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let initial_state_id = 42u128;
		let _ = state_file_io.create_initialized(&shard_id, initial_state_id).unwrap();

		let state_ids = vec![1u128, 2u128, 3u128];

		for state_id in state_ids.iter() {
			let _ = state_file_io.write(&shard_id, *state_id, 987345).unwrap();
		}

		let mut expected_size = state_ids.len() + 1;
		assert_eq!(expected_size, state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len());
		expected_size -= 1;

		for state_id in state_ids.iter() {
			state_file_io.remove(&shard_id, *state_id).unwrap();
			assert_matches!(
				state_file_io.load(&shard_id, *state_id),
				Err(Error::InvalidStateId(_))
			);
			assert_eq!(
				expected_size,
				state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len()
			);
			expected_size -= 1;
		}
	}

	#[test]
	fn initialize_with_shards_creates_empty_maps() {
		let shards = vec![ShardIdentifier::random(), ShardIdentifier::random()];
		let state_file_io = create_in_memory_state_file_io(shards.as_slice());

		assert_eq!(shards.len(), state_file_io.list_shards().unwrap().len());
		for shard in shards {
			assert!(state_file_io.list_state_ids_for_shard(&shard).unwrap().is_empty());
		}
	}

	fn assert_entry(
		state_file_io: &TestStateFileIo,
		shard_id: &ShardIdentifier,
		state_id: StateId,
		state: &TestState,
		state_hash: &StateHash,
	) {
		let (retrieved_hash, retrieved_state) =
			get_state_entry(&state_file_io, &shard_id, state_id);
		assert!(state_file_io.shard_exists(shard_id));
		assert_eq!(state_hash, &retrieved_hash);
		assert_eq!(state, &retrieved_state);
	}

	fn get_state_entry(
		state_file_io: &TestStateFileIo,
		shard_id: &ShardIdentifier,
		state_id: StateId,
	) -> (StateHash, TestState) {
		state_file_io
			.get_states_for_shard(shard_id)
			.unwrap()
			.get(&state_id)
			.unwrap()
			.clone()
	}

	fn create_in_memory_state_file_io(shards: &[ShardIdentifier]) -> TestStateFileIo {
		InMemoryStateFileIo::new(DefaultHasher::default(), shards)
	}

	fn create_empty_in_memory_state_file_io() -> TestStateFileIo {
		create_in_memory_state_file_io(&[])
	}
}
