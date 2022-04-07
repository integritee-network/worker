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
	state_snapshot_primitives::{
		extract_timestamp_from_file_name, initialize_shard_with_file, SnapshotHistory,
		StateFileMetaData,
	},
	state_snapshot_repository::StateSnapshotRepository,
};
use itp_types::ShardIdentifier;
use log::*;
use std::{
	collections::VecDeque, fmt::Debug, iter::FromIterator, marker::PhantomData, string::String,
	sync::Arc, vec::Vec,
};

/// Loads a state snapshot repository from existing shards directory with state files.
pub struct StateSnapshotRepositoryLoader<FileIo, State, HashType> {
	file_io: Arc<FileIo>,
	phantom_data: PhantomData<(State, HashType)>,
}

impl<FileIo, State, HashType> StateSnapshotRepositoryLoader<FileIo, State, HashType>
where
	FileIo: StateFileIo<StateType = State, HashType = HashType>,
	HashType: Copy + Eq + Debug,
{
	pub fn new(file_io: Arc<FileIo>) -> Self {
		StateSnapshotRepositoryLoader { file_io, phantom_data: Default::default() }
	}

	pub fn load_from_files(
		&self,
		snapshot_history_cache_size: usize,
	) -> Result<StateSnapshotRepository<FileIo, State, HashType>> {
		let snapshot_history = self.load_state_snapshot_history_from_files()?;

		StateSnapshotRepository::new(
			self.file_io.clone(),
			snapshot_history_cache_size,
			snapshot_history,
		)
	}

	fn load_state_snapshot_history_from_files(&self) -> Result<SnapshotHistory<HashType>> {
		let mut repository = SnapshotHistory::new();

		let shards = self.file_io.list_shards()?;
		debug!("Found {} shard directories to load state from", shards.len());

		for shard in shards {
			let files_names = self.file_io.list_shard_files(&shard)?;
			let timestamp_file_name_tuples =
				get_sorted_timestamps_for_file_names(files_names.as_slice());

			let mut file_meta_data: Vec<_> =
				self.map_to_file_metadata(&shard, timestamp_file_name_tuples);

			if file_meta_data.is_empty() {
				warn!(
					"No (valid) state files found for shard {:?}, initializing shard state",
					shard
				);
				let initial_file_metadata =
					initialize_shard_with_file(&shard, self.file_io.as_ref())?;
				file_meta_data.push(initial_file_metadata);
			} else {
				debug!(
					"Found {} state snapshot file(s) for shard {}, latest snapshot is {}",
					file_meta_data.len(),
					&shard,
					file_meta_data.first().map(|f| f.file_name.as_str()).unwrap_or_default()
				);
			}

			let snapshot_history = VecDeque::from_iter(file_meta_data);

			repository.insert(shard, snapshot_history);
		}
		Ok(repository)
	}

	fn map_to_file_metadata(
		&self,
		shard: &ShardIdentifier,
		sorted_timestamp_file_name_tuples: Vec<(u128, String)>,
	) -> Vec<StateFileMetaData<HashType>> {
		sorted_timestamp_file_name_tuples
			.into_iter()
			.flat_map(|timestamp_file_name_tuple| {
				self.file_io
					.compute_hash(shard, timestamp_file_name_tuple.1.as_str())
					.map_err(|e| {
						warn!(
								"Failed to compute hash for state snapshot file {}: {:?}, ignoring file as a result",
								timestamp_file_name_tuple.1, e
							);
					})
					.ok()
					.map(|h| StateFileMetaData::new(h, timestamp_file_name_tuple.1))
			})
			.collect()
	}
}

fn get_sorted_timestamps_for_file_names(file_names: &[String]) -> Vec<(u128, String)> {
	let mut timestamp_file_name_tuples: Vec<(u128, String)> =
		file_names
			.iter()
			.flat_map(|file_name| {
				extract_timestamp_from_file_name(file_name.as_str())
					.map(|t| (t, file_name.clone()))
					// Maybe there is a better way? Need to call a function in case of `None`.
					.ok_or_else(|| {
						warn!("Found state snapshot file ({}) that does not match pattern, ignoring it", file_name)
					})
					.ok()
			})
			.collect();

	timestamp_file_name_tuples.sort_by(|a, b| b.0.cmp(&a.0));
	timestamp_file_name_tuples
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::{
		in_memory_state_file_io::InMemoryStateFileIo,
		state_snapshot_primitives::generate_file_name_from_timestamp,
	};
	use itp_types::ShardIdentifier;
	use std::collections::hash_map::DefaultHasher;

	type TestState = u64;
	type TestStateHash = u64;
	type TestFileIo = InMemoryStateFileIo<TestState, DefaultHasher>;
	type TestLoader = StateSnapshotRepositoryLoader<TestFileIo, TestState, TestStateHash>;

	#[test]
	fn loading_from_empty_shard_directories_initializes_files() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (_, loader) = create_test_fixtures(shards.as_slice());

		let snapshot_history = loader.load_state_snapshot_history_from_files().unwrap();
		assert_eq!(shards.len(), snapshot_history.len());
		for snapshots in snapshot_history.values() {
			assert_eq!(1, snapshots.len());
		}
	}

	#[test]
	fn loading_without_shards_returns_empty_directory() {
		let (_, loader) = create_test_fixtures(&[]);

		let snapshot_history = loader.load_state_snapshot_history_from_files().unwrap();
		assert!(snapshot_history.is_empty());
	}

	#[test]
	fn loading_from_files_orders_by_timestamp() {
		let shards =
			vec![ShardIdentifier::random(), ShardIdentifier::random(), ShardIdentifier::random()];
		let (file_io, loader) = create_test_fixtures(shards.as_slice());

		add_files_with_timestamps(
			file_io.as_ref(),
			&shards[0],
			&[1_000_000, 2_000_000, 3_000_000, 4_000_000],
		);
		add_files_with_timestamps(file_io.as_ref(), &shards[1], &[10_000_000, 9_000_000]);
		add_files_with_timestamps(
			file_io.as_ref(),
			&shards[2],
			&[14_000_000, 11_000_000, 12_000_000],
		);

		let snapshot_history = loader.load_state_snapshot_history_from_files().unwrap();

		assert_eq!(shards.len(), snapshot_history.len());
		assert_latest_file_starts_with(&snapshot_history, &shards[0], "4000");
		assert_latest_file_starts_with(&snapshot_history, &shards[1], "10000");
		assert_latest_file_starts_with(&snapshot_history, &shards[2], "14000");
	}

	#[test]
	fn ignore_invalid_file_names() {
		let shard = ShardIdentifier::random();
		let (file_io, loader) = create_test_fixtures(&[shard]);

		// Only 2 of these file names are valid
		file_io.create_initialized(&shard, "oijef.bin").unwrap();
		file_io.create_initialized(&shard, "other-invalid_state.bin").unwrap();
		file_io
			.create_initialized(&shard, generate_file_name_from_timestamp(8_000_000).as_str())
			.unwrap();
		file_io
			.create_initialized(&shard, generate_file_name_from_timestamp(4_000_000).as_str())
			.unwrap();

		let snapshot_history = loader.load_state_snapshot_history_from_files().unwrap();
		assert_eq!(2, snapshot_history.get(&shard).unwrap().len());
		assert_latest_file_starts_with(&snapshot_history, &shard, "8000000");
	}

	fn add_files_with_timestamps(
		file_io: &TestFileIo,
		shard: &ShardIdentifier,
		timestamps: &[u128],
	) {
		for timestamp in timestamps {
			add_file_with_timestamp(file_io, shard, *timestamp);
		}
	}

	fn add_file_with_timestamp(file_io: &TestFileIo, shard: &ShardIdentifier, timestamp: u128) {
		file_io
			.create_initialized(shard, generate_file_name_from_timestamp(timestamp).as_str())
			.unwrap();
	}

	fn assert_latest_file_starts_with(
		snapshot_history: &SnapshotHistory<TestStateHash>,
		shard: &ShardIdentifier,
		str: &str,
	) {
		assert!(snapshot_history.get(shard).unwrap().front().unwrap().file_name.starts_with(str))
	}

	fn create_test_fixtures(shards: &[ShardIdentifier]) -> (Arc<TestFileIo>, TestLoader) {
		let file_io = Arc::new(TestFileIo::new(DefaultHasher::default(), shards));
		let loader = StateSnapshotRepositoryLoader::new(file_io.clone());
		(file_io, loader)
	}
}
