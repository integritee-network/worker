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
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesType};
use itp_types::{ShardIdentifier, H256};
use sp_core::blake2_256;
use std::{boxed::Box, collections::HashMap, sync::Arc, vec::Vec};

type StateHash = H256;
type ShardDirectory<State> = HashMap<StateId, (StateHash, State)>;
type ShardsRootDirectory<State> = HashMap<ShardIdentifier, ShardDirectory<State>>;
type InnerStateSelector<State, ExternalState> =
	Box<dyn Fn(&ExternalState) -> State + Send + Sync + 'static>;
type ExternalStateGenerator<State, ExternalState> =
	Box<dyn Fn(State) -> ExternalState + Send + Sync + 'static>;

/// State file I/O using (unencrypted) in-memory representation of the state files.
/// Can be used as mock for testing.
pub struct InMemoryStateFileIo<State, ExternalState>
where
	State: Clone + Default + Encode,
{
	emulated_shard_directory: RwLock<ShardsRootDirectory<State>>,
	state_selector: InnerStateSelector<State, ExternalState>,
	external_state_generator: ExternalStateGenerator<State, ExternalState>,
}

impl<State, ExternalState> InMemoryStateFileIo<State, ExternalState>
where
	State: Clone + Default + Encode,
{
	#[allow(unused)]
	pub fn new(
		shards: &[ShardIdentifier],
		state_selector: InnerStateSelector<State, ExternalState>,
		external_state_generator: ExternalStateGenerator<State, ExternalState>,
	) -> Self {
		let shard_hash_map: HashMap<_, _> =
			shards.iter().map(|s| (*s, ShardDirectory::<State>::default())).collect();

		InMemoryStateFileIo {
			emulated_shard_directory: RwLock::new(shard_hash_map),
			state_selector,
			external_state_generator,
		}
	}

	#[cfg(any(test, feature = "test"))]
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
		blake2_256(&encoded_state).into()
	}

	fn generate_state_entry(&self, state: State) -> (StateHash, State) {
		let state_hash = self.compute_state_hash(&state);
		(state_hash, state)
	}
}

impl<State, ExternalState> StateFileIo for InMemoryStateFileIo<State, ExternalState>
where
	State: Clone + Default + Encode,
{
	type StateType = ExternalState;
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
		let inner_state = states_for_shard
			.get(&state_id)
			.map(|(_, s)| -> State { s.clone() })
			.ok_or_else(|| Error::InvalidStateId(state_id))?;

		Ok((self.external_state_generator)(inner_state))
	}

	fn compute_hash(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::HashType> {
		let state = self.load(shard_identifier, state_id)?;
		Ok(self.compute_state_hash(&(self.state_selector)(&state)))
	}

	fn initialize_shard(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
		external_state: &Self::StateType,
	) -> Result<Self::HashType> {
		let mut directory_lock =
			self.emulated_shard_directory.write().map_err(|_| Error::LockPoisoning)?;

		let states_for_shard = directory_lock.entry(*shard_identifier).or_default();
		let state_entry = states_for_shard
			.entry(state_id)
			.or_insert_with(|| self.generate_state_entry((self.state_selector)(external_state)));
		Ok(state_entry.0)
	}

	fn write(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
		external_state: &Self::StateType,
	) -> Result<Self::HashType> {
		let mut directory_lock =
			self.emulated_shard_directory.write().map_err(|_| Error::LockPoisoning)?;

		let states_for_shard = directory_lock.entry(*shard_identifier).or_default();

		let inner_state = (self.state_selector)(external_state);
		let state_hash = self.compute_state_hash(&inner_state);

		*states_for_shard.entry(state_id).or_default() = (state_hash, inner_state);

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
			.ok_or_else(|| Error::InvalidStateId(state_id))
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

pub fn create_sgx_externalities_in_memory_state_io(
) -> Arc<InMemoryStateFileIo<SgxExternalitiesType, SgxExternalities>> {
	create_in_memory_externalities_state_io(&[])
}

fn create_in_memory_externalities_state_io(
	shards: &[ShardIdentifier],
) -> Arc<InMemoryStateFileIo<SgxExternalitiesType, SgxExternalities>> {
	Arc::new(InMemoryStateFileIo::new(
		shards,
		sgx_externalities_selector(),
		sgx_externalities_wrapper(),
	))
}

fn sgx_externalities_selector() -> InnerStateSelector<SgxExternalitiesType, SgxExternalities> {
	Box::new(|s| s.state.clone())
}

fn sgx_externalities_wrapper() -> ExternalStateGenerator<SgxExternalitiesType, SgxExternalities> {
	Box::new(|s| SgxExternalities { state: s, state_diff: Default::default() })
}

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use crate::file_io::list_shards;
	use std::path::Path;

	pub fn create_in_memory_state_io_from_shards_directories(
		path: &Path,
	) -> Result<Arc<InMemoryStateFileIo<SgxExternalitiesType, SgxExternalities>>> {
		let shards: Vec<ShardIdentifier> =
			list_shards(path).map(|iter| iter.collect()).unwrap_or_default();
		Ok(create_in_memory_externalities_state_io(&shards))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::assert_matches::assert_matches;

	type TestState = u64;
	type TestStateFileIo = InMemoryStateFileIo<TestState, TestState>;

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
		let _ = state_file_io.initialize_shard(&shard_id, 1234, &Default::default()).unwrap();

		assert_matches!(state_file_io.load(&shard_id, 12345), Err(Error::InvalidStateId(12345)));
	}

	#[test]
	fn create_initialized_when_shard_already_exists_works() {
		let shard = ShardIdentifier::random();
		let state_file_io = create_in_memory_state_file_io(&[shard]);

		assert!(state_file_io.initialize_shard(&shard, 1245, &Default::default()).is_ok());
	}

	#[test]
	fn create_initialized_adds_default_state() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let state_id = 31081984u128;
		let state_hash = state_file_io
			.initialize_shard(&shard_id, state_id, &Default::default())
			.unwrap();

		assert_eq!(1, state_file_io.list_shards().unwrap().len());
		assert_eq!(TestState::default(), state_file_io.load(&shard_id, state_id).unwrap());
		assert_eq!(1, state_file_io.list_state_ids_for_shard(&shard_id).unwrap().len());

		assert_entry(&state_file_io, &shard_id, state_id, &TestState::default(), &state_hash);
	}

	#[test]
	fn write_works_when_no_previous_shard_or_file_exists() {
		let state_file_io = create_empty_in_memory_state_file_io();
		let shard_id = ShardIdentifier::random();
		let state_id = 23u128;
		let test_state = 42u64;

		let state_hash = state_file_io.write(&shard_id, state_id, &test_state).unwrap();

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
		let _ = state_file_io
			.initialize_shard(&shard_id, state_id, &Default::default())
			.unwrap();

		let test_state = 4256u64;
		let state_hash = state_file_io.write(&shard_id, state_id, &test_state).unwrap();

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
		let _ = state_file_io
			.initialize_shard(&shard_id, initial_state_id, &Default::default())
			.unwrap();

		let state_ids = vec![1u128, 2u128, 3u128];

		for state_id in state_ids.iter() {
			let _ = state_file_io.write(&shard_id, *state_id, &987345).unwrap();
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
		InMemoryStateFileIo::new(shards, Box::new(|x| *x), Box::new(|x| x))
	}

	fn create_empty_in_memory_state_file_io() -> TestStateFileIo {
		create_in_memory_state_file_io(&[])
	}
}
