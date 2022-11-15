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
	error::Result,
	file_io::StateFileIo,
	state_initializer::InitializeState,
	state_snapshot_primitives::{
		initialize_shard_with_snapshot, SnapshotHistory, StateId, StateSnapshotMetaData,
	},
	state_snapshot_repository::StateSnapshotRepository,
};
use itp_hashing::Hash;
use itp_types::ShardIdentifier;
use log::*;
use std::{collections::VecDeque, fmt::Debug, iter::FromIterator, sync::Arc, vec::Vec};

/// Loads a state snapshot repository from existing shards directory with state files.
pub struct StateSnapshotRepositoryLoader<FileIo, StateInitializer> {
	file_io: Arc<FileIo>,
	state_initializer: Arc<StateInitializer>,
}

impl<FileIo, StateInitializer> StateSnapshotRepositoryLoader<FileIo, StateInitializer>
where
	FileIo: StateFileIo,
	<FileIo as StateFileIo>::HashType: Copy + Eq + Debug,
	<FileIo as StateFileIo>::StateType: Clone + Hash<FileIo::HashType>,
	StateInitializer: InitializeState<StateType = FileIo::StateType>,
{
	pub fn new(file_io: Arc<FileIo>, state_initializer: Arc<StateInitializer>) -> Self {
		Self { file_io, state_initializer }
	}

	/// Load a state snapshot repository from an existing set of files and directories.
	pub fn load_snapshot_repository(
		&self,
		snapshot_history_cache_size: usize,
	) -> Result<StateSnapshotRepository<FileIo>> {
		let snapshot_history = self.load_and_initialize_state_snapshot_history()?;

		StateSnapshotRepository::new(
			self.file_io.clone(),
			snapshot_history_cache_size,
			snapshot_history,
		)
	}

	fn load_and_initialize_state_snapshot_history(
		&self,
	) -> Result<SnapshotHistory<FileIo::HashType>> {
		let mut repository = SnapshotHistory::new();

		let shards = self.file_io.list_shards()?;
		debug!("Found {} shard(s) to load state from", shards.len());

		for shard in shards {
			let mut state_ids = self.file_io.list_state_ids_for_shard(&shard)?;
			// Sort by id (which are timestamp), highest, i.e. newest, first
			state_ids.sort_unstable();
			state_ids.reverse();

			let mut snapshot_metadata: Vec<_> = self.map_to_snapshot_metadata(&shard, state_ids);

			if snapshot_metadata.is_empty() {
				warn!(
					"No (valid) states found for shard {:?}, initializing empty shard state",
					shard
				);
				let initial_state = self.state_initializer.initialize()?;
				let initial_snapshot_metadata =
					initialize_shard_with_snapshot(&shard, self.file_io.as_ref(), &initial_state)?;
				snapshot_metadata.push(initial_snapshot_metadata);
			} else {
				debug!(
					"Found {} state snapshot(s) for shard {}, latest snapshot is {}",
					snapshot_metadata.len(),
					&shard,
					snapshot_metadata.first().map(|f| f.state_id).unwrap_or_default()
				);
			}

			let snapshot_history = VecDeque::from_iter(snapshot_metadata);

			repository.insert(shard, snapshot_history);
		}
		Ok(repository)
	}

	fn map_to_snapshot_metadata(
		&self,
		shard: &ShardIdentifier,
		state_ids: Vec<StateId>,
	) -> Vec<StateSnapshotMetaData<FileIo::HashType>> {
		state_ids
			.into_iter()
			.flat_map(|state_id| match self.file_io.compute_hash(shard, state_id) {
				Ok(hash) => Some(StateSnapshotMetaData::new(hash, state_id)),
				Err(e) => {
					warn!(
								"Failed to compute hash for state snapshot with id {}: {:?}, ignoring snapshot as a result",
								state_id, e
							);
					None
				},
			})
			.collect()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		in_memory_state_file_io::InMemoryStateFileIo,
		test::mocks::initialize_state_mock::InitializeStateMock,
	};
	use codec::Encode;
	use itp_types::H256;
	use sp_core::blake2_256;

	#[derive(Encode, Clone, Default, Copy)]
	struct TestState(pub u64);

	type TestStateHash = H256;
	type TestFileIo = InMemoryStateFileIo<TestState, TestState>;
	type TestStateInitializer = InitializeStateMock<TestState>;
	type TestLoader = StateSnapshotRepositoryLoader<TestFileIo, TestStateInitializer>;

	impl Hash<TestStateHash> for TestState {
		fn hash(&self) -> TestStateHash {
			blake2_256(&self.encode()).into()
		}
	}

	#[test]
	fn loading_from_empty_shard_directories_initializes_files() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (_, loader) = create_test_fixtures(shards.as_slice());

		let snapshot_history = loader.load_and_initialize_state_snapshot_history().unwrap();
		assert_eq!(shards.len(), snapshot_history.len());
		for snapshots in snapshot_history.values() {
			assert_eq!(1, snapshots.len());
		}
	}

	#[test]
	fn loading_without_shards_returns_empty_directory() {
		let (_, loader) = create_test_fixtures(&[]);

		let snapshot_history = loader.load_and_initialize_state_snapshot_history().unwrap();
		assert!(snapshot_history.is_empty());
	}

	#[test]
	fn loading_from_files_orders_by_timestamp() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (file_io, loader) = create_test_fixtures(shards.as_slice());

		add_state_snapshots(
			file_io.as_ref(),
			&shards[0],
			&[1_000_000, 2_000_000, 3_000_000, 4_000_000],
		);
		add_state_snapshots(file_io.as_ref(), &shards[1], &[10_000_000, 9_000_000]);
		add_state_snapshots(file_io.as_ref(), &shards[2], &[14_000_000, 11_000_000, 12_000_000]);

		let snapshot_history = loader.load_and_initialize_state_snapshot_history().unwrap();

		assert_eq!(shards.len(), snapshot_history.len());
		assert_latest_state_id(&snapshot_history, &shards[0], 4_000_000);
		assert_latest_state_id(&snapshot_history, &shards[1], 10_000_000);
		assert_latest_state_id(&snapshot_history, &shards[2], 14_000_000);
	}

	fn add_state_snapshots(file_io: &TestFileIo, shard: &ShardIdentifier, state_ids: &[StateId]) {
		for state_id in state_ids {
			add_snapshot_with_state_ids(file_io, shard, *state_id);
		}
	}

	fn add_snapshot_with_state_ids(
		file_io: &TestFileIo,
		shard: &ShardIdentifier,
		state_id: StateId,
	) {
		file_io.initialize_shard(shard, state_id, &Default::default()).unwrap();
	}

	fn assert_latest_state_id(
		snapshot_history: &SnapshotHistory<TestStateHash>,
		shard: &ShardIdentifier,
		state_id: StateId,
	) {
		assert_eq!(snapshot_history.get(shard).unwrap().front().unwrap().state_id, state_id)
	}

	fn create_test_fixtures(shards: &[ShardIdentifier]) -> (Arc<TestFileIo>, TestLoader) {
		let file_io = Arc::new(TestFileIo::new(shards, Box::new(|x| *x), Box::new(|x| x)));
		let state_initializer = Arc::new(TestStateInitializer::new(Default::default()));
		let loader = StateSnapshotRepositoryLoader::new(file_io.clone(), state_initializer);
		(file_io, loader)
	}
}
