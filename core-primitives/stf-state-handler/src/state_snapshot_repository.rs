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
	file_io::StateFileIo,
	state_snapshot_primitives::{
		generate_current_timestamp_state_id, initialize_shard_with_snapshot, SnapshotHistory,
		StateId, StateSnapshotMetaData,
	},
};
use core::ops::RangeBounds;
use itp_types::ShardIdentifier;
use log::*;
use std::{collections::VecDeque, fmt::Debug, format, marker::PhantomData, sync::Arc, vec::Vec};

/// Trait for versioned state access. Manages history of state snapshots.
pub trait VersionedStateAccess {
	type StateType;
	type HashType;

	/// Load the latest version of the state.
	fn load_latest(&self, shard_identifier: &ShardIdentifier) -> Result<Self::StateType>;

	/// Update the state, returning the hash of the state.
	fn update(
		&mut self,
		shard_identifier: &ShardIdentifier,
		state: Self::StateType,
	) -> Result<Self::HashType>;

	/// Reverts the state of a given shard to a state version identified by a state hash.
	fn revert_to(
		&mut self,
		shard_identifier: &ShardIdentifier,
		state_hash: &Self::HashType,
	) -> Result<Self::StateType>;

	/// Initialize a new shard.
	fn initialize_new_shard(&mut self, shard_identifier: ShardIdentifier)
		-> Result<Self::HashType>;

	/// Checks if a shard for a given identifier exists.
	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool;

	/// Lists all shards.
	fn list_shards(&self) -> Result<Vec<ShardIdentifier>>;
}

/// State snapshot repository.
///
/// Keeps versions of state snapshots, cycles them in a fixed-size circular buffer.
/// Creates a state snapshot for each write/update operation. Allows reverting to a specific snapshot,
/// identified by a state hash. Snapshot files names includes a timestamp to be unique.
pub struct StateSnapshotRepository<FileIo, State, HashType> {
	file_io: Arc<FileIo>,
	snapshot_history_cache_size: usize,
	snapshot_history: SnapshotHistory<HashType>,
	phantom_data: PhantomData<State>,
}

impl<FileIo, State, HashType> StateSnapshotRepository<FileIo, State, HashType>
where
	FileIo: StateFileIo<StateType = State, HashType = HashType>,
	HashType: Copy + Eq + Debug,
{
	/// Constructor, initialized with no shards or snapshot history.
	pub fn empty(file_io: Arc<FileIo>, snapshot_history_cache_size: usize) -> Result<Self> {
		Self::new(file_io, snapshot_history_cache_size, SnapshotHistory::default())
	}

	/// Constructor to initialize the repository with shards and snapshot history.
	///
	/// Crate private, to be used by the loader.
	pub(crate) fn new(
		file_io: Arc<FileIo>,
		snapshot_history_cache_size: usize,
		snapshot_history: SnapshotHistory<HashType>,
	) -> Result<Self> {
		if snapshot_history_cache_size == 0usize {
			return Err(Error::ZeroCacheSize)
		}

		Ok(StateSnapshotRepository {
			file_io,
			snapshot_history_cache_size,
			snapshot_history,
			phantom_data: Default::default(),
		})
	}

	fn get_snapshot_history_mut(
		&mut self,
		shard_identifier: &ShardIdentifier,
	) -> Result<&mut VecDeque<StateSnapshotMetaData<HashType>>> {
		self.snapshot_history
			.get_mut(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))
	}

	fn get_snapshot_history(
		&self,
		shard_identifier: &ShardIdentifier,
	) -> Result<&VecDeque<StateSnapshotMetaData<HashType>>> {
		self.snapshot_history
			.get(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))
	}

	fn get_latest_snapshot_metadata(
		&self,
		shard_identifier: &ShardIdentifier,
	) -> Result<&StateSnapshotMetaData<HashType>> {
		let snapshot_history = self.get_snapshot_history(shard_identifier)?;
		snapshot_history.front().ok_or(Error::EmptyRepository)
	}

	fn prune_snapshot_history_by_range<R: RangeBounds<usize>>(
		&mut self,
		shard_identifier: &ShardIdentifier,
		range: R,
	) -> Result<()> {
		let state_snapshots_to_remove = self
			.get_snapshot_history_mut(shard_identifier)?
			.drain(range)
			.collect::<Vec<_>>();

		self.remove_snapshots(shard_identifier, state_snapshots_to_remove.as_slice());
		Ok(())
	}

	/// Remove snapshots referenced by metadata.
	/// Does not stop on error, it's guaranteed to call `remove` on all elements.
	/// Logs any errors that occur.
	fn remove_snapshots(
		&self,
		shard_identifier: &ShardIdentifier,
		snapshots_metadata: &[StateSnapshotMetaData<HashType>],
	) {
		for snapshot_metadata in snapshots_metadata {
			if let Err(e) = self.file_io.remove(shard_identifier, snapshot_metadata.state_id) {
				// We just log an error, don't want to return the error here, because the operation
				// in general was successful, just a side-effect that failed.
				error!("Failed to remove state, with id '{}': {:?}", snapshot_metadata.state_id, e);
			}
		}
	}

	fn write_new_state(
		&self,
		shard_identifier: &ShardIdentifier,
		state: State,
	) -> Result<(HashType, StateId)> {
		let state_id = generate_current_timestamp_state_id();
		let state_hash = self.file_io.write(shard_identifier, state_id, state)?;
		Ok((state_hash, state_id))
	}

	fn load_state(
		&self,
		shard_identifier: &ShardIdentifier,
		snapshot_metadata: &StateSnapshotMetaData<HashType>,
	) -> Result<State> {
		self.file_io.load(shard_identifier, snapshot_metadata.state_id)
	}
}

impl<FileIo, State, HashType> VersionedStateAccess
	for StateSnapshotRepository<FileIo, State, HashType>
where
	FileIo: StateFileIo<StateType = State, HashType = HashType>,
	HashType: Copy + Eq + Debug,
{
	type StateType = State;
	type HashType = HashType;

	fn load_latest(&self, shard_identifier: &ShardIdentifier) -> Result<Self::StateType> {
		let latest_snapshot_metadata = self.get_latest_snapshot_metadata(shard_identifier)?;
		self.file_io.load(shard_identifier, latest_snapshot_metadata.state_id)
	}

	fn update(
		&mut self,
		shard_identifier: &ShardIdentifier,
		state: Self::StateType,
	) -> Result<Self::HashType> {
		if !self.shard_exists(shard_identifier) {
			return Err(Error::InvalidShard(*shard_identifier))
		}

		let (state_hash, state_id) = self.write_new_state(shard_identifier, state)?;
		let cache_size = self.snapshot_history_cache_size;

		let snapshot_history = self.get_snapshot_history_mut(shard_identifier)?;
		snapshot_history.push_front(StateSnapshotMetaData::new(state_hash, state_id));

		// In case we're above max queue size we remove the oldest entries and corresponding files
		if snapshot_history.len() > cache_size {
			self.prune_snapshot_history_by_range(shard_identifier, cache_size..)?;
		}

		Ok(state_hash)
	}

	fn revert_to(
		&mut self,
		shard_identifier: &ShardIdentifier,
		state_hash: &Self::HashType,
	) -> Result<Self::StateType> {
		let snapshot_history = self.get_snapshot_history(shard_identifier)?;

		// We use `position()` instead of `find()`, because it then allows us to easily drain
		// all the newer states.
		let snapshot_metadata_index = snapshot_history
			.iter()
			.position(|fmd| fmd.state_hash == *state_hash)
			.ok_or_else(|| Error::StateNotFoundInRepository(format!("{:?}", state_hash)))?;

		// Should never fail, since we got the index from above, with `position()`.
		let snapshot_metadata = snapshot_history
			.get(snapshot_metadata_index)
			.ok_or_else(|| Error::StateNotFoundInRepository(format!("{:?}", state_hash)))?;

		let state = self.load_state(shard_identifier, snapshot_metadata)?;

		// Remove any state versions newer than the one we're resetting to
		// (do this irreversible operation last, to ensure the loading has succeeded)
		self.prune_snapshot_history_by_range(shard_identifier, ..snapshot_metadata_index)?;

		Ok(state)
	}

	fn initialize_new_shard(
		&mut self,
		shard_identifier: ShardIdentifier,
	) -> Result<Self::HashType> {
		if let Some(state_snapshots) = self.snapshot_history.get(&shard_identifier) {
			warn!("Shard ({:?}) already exists, will not initialize again", shard_identifier);
			return state_snapshots.front().map(|s| s.state_hash).ok_or(Error::EmptyRepository)
		}

		let snapshot_metadata =
			initialize_shard_with_snapshot(&shard_identifier, self.file_io.as_ref())?;

		let state_hash = snapshot_metadata.state_hash;
		self.snapshot_history
			.insert(shard_identifier, VecDeque::from([snapshot_metadata]));
		Ok(state_hash)
	}

	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
		self.snapshot_history.get(shard_identifier).is_some()
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.snapshot_history.keys().cloned().collect())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		in_memory_state_file_io::InMemoryStateFileIo,
		state_snapshot_repository_loader::StateSnapshotRepositoryLoader,
	};
	use std::{collections::hash_map::DefaultHasher, vec};

	type TestState = u64;
	type TestStateHash = u64;
	type TestFileIo = InMemoryStateFileIo<TestState, DefaultHasher>;
	type TestSnapshotRepository = StateSnapshotRepository<TestFileIo, TestState, TestStateHash>;

	const TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE: usize = 3;

	#[test]
	fn new_with_zero_cache_size_returns_error() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let file_io = create_test_file_io(shards.as_slice());

		assert!(TestSnapshotRepository::empty(file_io.clone(), 0usize).is_err());
	}

	#[test]
	fn upon_new_all_shards_are_initialized() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (file_io, state_snapshot_repository) = create_state_snapshot_repository(
			shards.as_slice(),
			TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE,
		);

		assert_eq!(shards.len(), file_io.list_shards().unwrap().len());
		assert_eq!(shards.len(), state_snapshot_repository.snapshot_history.len());
		assert_eq!(shards.len(), state_snapshot_repository.list_shards().unwrap().len());
		for states_per_shard in state_snapshot_repository.snapshot_history.values() {
			assert_eq!(1, states_per_shard.len());
		}
		for shard in shards {
			assert!(state_snapshot_repository.load_latest(&shard).is_ok());
			assert!(state_snapshot_repository.shard_exists(&shard));
		}
	}

	#[test]
	fn update_latest_creates_new_state_file() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (file_io, mut state_snapshot_repository) = create_state_snapshot_repository(
			shards.as_slice(),
			TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE,
		);

		let shard_to_update = shards.get(1).unwrap();
		assert_eq!(1, file_io.get_states_for_shard(shard_to_update).unwrap().len());

		let new_state = 1234u64;

		let _ = state_snapshot_repository.update(shard_to_update, new_state).unwrap();

		let snapshot_history =
			state_snapshot_repository.snapshot_history.get(shard_to_update).unwrap();
		assert_eq!(2, snapshot_history.len());
		assert_eq!(new_state, state_snapshot_repository.load_latest(shard_to_update).unwrap());
		assert_eq!(2, file_io.get_states_for_shard(shard_to_update).unwrap().len());
	}

	#[test]
	fn update_latest_prunes_states_when_above_cache_size() {
		let shard_id = ShardIdentifier::random();
		let (file_io, mut state_snapshot_repository) =
			create_state_snapshot_repository(&[shard_id], TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE);

		let states = vec![1u64, 2u64, 3u64, 4u64, 5u64, 6u64];
		assert!(states.len() > TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE); // ensures we have pruning

		states.iter().for_each(|state| {
			let _ = state_snapshot_repository.update(&shard_id, *state).unwrap();
		});

		let snapshot_history = state_snapshot_repository.snapshot_history.get(&shard_id).unwrap();
		assert_eq!(TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE, snapshot_history.len());
		assert_eq!(
			*states.last().unwrap(),
			state_snapshot_repository.load_latest(&shard_id).unwrap()
		);
		assert_eq!(
			TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE,
			file_io.get_states_for_shard(&shard_id).unwrap().len()
		);
	}

	#[test]
	fn update_latest_with_invalid_shard_returns_error_without_modification() {
		let shard_id = ShardIdentifier::random();
		let (file_io, mut state_snapshot_repository) =
			create_state_snapshot_repository(&[shard_id], TEST_SNAPSHOT_REPOSITORY_CACHE_SIZE);

		assert!(state_snapshot_repository.update(&ShardIdentifier::random(), 45).is_err());

		let snapshot_history = state_snapshot_repository.snapshot_history.get(&shard_id).unwrap();
		assert_eq!(1, snapshot_history.len());
		assert_eq!(0u64, state_snapshot_repository.load_latest(&shard_id).unwrap());
		assert_eq!(1, file_io.get_states_for_shard(&shard_id).unwrap().len());
	}

	#[test]
	fn revert_to_removes_version_newer_than_target_hash() {
		let shard_id = ShardIdentifier::random();
		let (file_io, mut state_snapshot_repository) =
			create_state_snapshot_repository(&[shard_id], 6);

		let states = vec![1u64, 2u64, 3u64, 4u64, 5u64];

		let state_hashes = states
			.iter()
			.map(|state| state_snapshot_repository.update(&shard_id, *state).unwrap())
			.collect::<Vec<_>>();
		let revert_target_hash = state_hashes.get(1).unwrap();

		let reverted_state =
			state_snapshot_repository.revert_to(&shard_id, revert_target_hash).unwrap();

		assert_eq!(2u64, reverted_state);
		assert_eq!(3, state_snapshot_repository.snapshot_history.get(&shard_id).unwrap().len()); // because we have initialized version '0' as well
		assert_eq!(2u64, state_snapshot_repository.load_latest(&shard_id).unwrap());
		assert_eq!(3, file_io.get_states_for_shard(&shard_id).unwrap().len());
	}

	#[test]
	fn initializing_new_shard_works() {
		let (_, mut state_snapshot_repository) = create_state_snapshot_repository(&[], 2);

		let shard_id = ShardIdentifier::random();

		assert!(state_snapshot_repository.load_latest(&shard_id).is_err());
		assert!(state_snapshot_repository.list_shards().unwrap().is_empty());

		let _hash = state_snapshot_repository.initialize_new_shard(shard_id).unwrap();

		assert!(state_snapshot_repository.load_latest(&shard_id).is_ok());
		assert_eq!(1, state_snapshot_repository.list_shards().unwrap().len());
	}

	#[test]
	fn initialize_new_state_when_shard_already_exists_returns_ok() {
		let shard_id = ShardIdentifier::random();
		let (_, mut state_snapshot_repository) = create_state_snapshot_repository(&[shard_id], 2);

		let _hash = state_snapshot_repository.initialize_new_shard(shard_id).unwrap();

		assert!(state_snapshot_repository.load_latest(&shard_id).is_ok());
		assert_eq!(1, state_snapshot_repository.list_shards().unwrap().len());
	}

	fn create_state_snapshot_repository(
		shards: &[ShardIdentifier],
		snapshot_history_size: usize,
	) -> (Arc<TestFileIo>, TestSnapshotRepository) {
		let file_io = create_test_file_io(shards);
		let repository_loader = StateSnapshotRepositoryLoader::new(file_io.clone());
		(file_io, repository_loader.load_snapshot_repository(snapshot_history_size).unwrap())
	}

	fn create_test_file_io(shards: &[ShardIdentifier]) -> Arc<TestFileIo> {
		Arc::new(TestFileIo::new(DefaultHasher::default(), shards))
	}
}
