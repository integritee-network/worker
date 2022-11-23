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

use crate::{
	error::{Error, Result},
	handle_state::HandleState,
	query_shard_state::QueryShardState,
	state_initializer::InitializeState,
	state_snapshot_repository::VersionedStateAccess,
};
use itp_hashing::Hash;
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_state_observer::traits::UpdateState;
use itp_types::ShardIdentifier;
use std::{collections::HashMap, sync::Arc, vec::Vec};

type StatesMap<State, Hash> = HashMap<ShardIdentifier, (State, Hash)>;

/// Implementation of the `HandleState` trait.
///
/// Responsible for handling any state instances. Holds a map with all the latest states for each shard.
/// In addition, uses the snapshot repository to save file snapshots of a state.
pub struct StateHandler<Repository, StateObserver, StateInitializer>
where
	Repository: VersionedStateAccess,
{
	state_snapshot_repository: RwLock<Repository>,
	states_map_lock: RwLock<StatesMap<Repository::StateType, Repository::HashType>>,
	state_observer: Arc<StateObserver>,
	state_initializer: Arc<StateInitializer>,
}

impl<Repository, StateObserver, StateInitializer>
	StateHandler<Repository, StateObserver, StateInitializer>
where
	Repository: VersionedStateAccess,
	Repository::StateType: Hash<Repository::HashType>,
	StateObserver: UpdateState<Repository::StateType>,
	StateInitializer: InitializeState<StateType = Repository::StateType>,
{
	/// Creates a new instance WITHOUT loading any state from the repository.
	/// Results in an empty states map.
	pub fn new(
		state_snapshot_repository: Repository,
		state_observer: Arc<StateObserver>,
		state_initializer: Arc<StateInitializer>,
	) -> Self {
		Self::new_with_states_map(
			state_snapshot_repository,
			state_observer,
			state_initializer,
			Default::default(),
		)
	}

	/// Create a new state handler and initialize its state map with the
	/// states that are available in the snapshot repository.
	pub fn load_from_repository(
		state_snapshot_repository: Repository,
		state_observer: Arc<StateObserver>,
		state_initializer: Arc<StateInitializer>,
	) -> Result<Self> {
		let states_map = Self::load_all_latest_snapshots(&state_snapshot_repository)?;
		Ok(Self::new_with_states_map(
			state_snapshot_repository,
			state_observer,
			state_initializer,
			states_map,
		))
	}

	fn new_with_states_map(
		state_snapshot_repository: Repository,
		state_observer: Arc<StateObserver>,
		state_initializer: Arc<StateInitializer>,
		states_map: StatesMap<Repository::StateType, Repository::HashType>,
	) -> Self {
		StateHandler {
			state_snapshot_repository: RwLock::new(state_snapshot_repository),
			states_map_lock: RwLock::new(states_map),
			state_observer,
			state_initializer,
		}
	}

	fn load_all_latest_snapshots(
		state_snapshot_repository: &Repository,
	) -> Result<StatesMap<Repository::StateType, Repository::HashType>> {
		let shards = state_snapshot_repository.list_shards()?;

		let r = shards
			.into_iter()
			.map(|shard| state_snapshot_repository.load_latest(&shard).map(|state| (state, shard)))
			// Fill the pairs for state and shard into a map.
			// Log an error for cases where state could not be loaded.
			.fold(StatesMap::default(), |mut map, x| {
				match x {
					Ok((state, shard)) => {
						let state_hash = state.hash();
						map.insert(shard, (state, state_hash));
					},
					Err(e) => {
						log::error!("Failed to load state from snapshot repository {:?}", e);
					},
				};
				map
			});

		Ok(r)
	}

	fn update_state_snapshot(
		&self,
		shard: &ShardIdentifier,
		state: &Repository::StateType,
		state_hash: Repository::HashType,
	) -> Result<()> {
		let mut state_snapshots_lock =
			self.state_snapshot_repository.write().map_err(|_| Error::LockPoisoning)?;

		state_snapshots_lock.update(shard, state, state_hash)
	}
}

impl<Repository, StateObserver, StateInitializer> HandleState
	for StateHandler<Repository, StateObserver, StateInitializer>
where
	Repository: VersionedStateAccess,
	Repository::StateType: SgxExternalitiesTrait + Hash<Repository::HashType>,
	Repository::HashType: Copy,
	StateObserver: UpdateState<Repository::StateType>,
	StateInitializer: InitializeState<StateType = Repository::StateType>,
{
	type WriteLockPayload = StatesMap<Repository::StateType, Repository::HashType>;
	type StateT = Repository::StateType;
	type HashType = Repository::HashType;

	fn initialize_shard(&self, shard: ShardIdentifier) -> Result<Self::HashType> {
		let initialized_state = self.state_initializer.initialize()?;
		self.reset(initialized_state, &shard)
	}

	fn execute_on_current<E, R>(&self, shard: &ShardIdentifier, executing_function: E) -> Result<R>
	where
		E: FnOnce(&Self::StateT, Self::HashType) -> R,
	{
		self.states_map_lock
			.read()
			.map_err(|_| Error::LockPoisoning)?
			.get(shard)
			.map(|(state, state_hash)| executing_function(state, *state_hash))
			.ok_or_else(|| Error::InvalidShard(*shard))
	}

	fn load_cloned(&self, shard: &ShardIdentifier) -> Result<(Self::StateT, Self::HashType)> {
		let state = self
			.states_map_lock
			.read()
			.map_err(|_| Error::LockPoisoning)?
			.get(shard)
			.ok_or_else(|| Error::InvalidShard(*shard))?
			.clone();

		Ok(state)
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, Self::StateT)> {
		let state_write_lock = self.states_map_lock.write().map_err(|_| Error::LockPoisoning)?;
		let state_clone = state_write_lock
			.get(shard)
			.ok_or_else(|| Error::InvalidShard(*shard))?
			.0
			.clone();

		Ok((state_write_lock, state_clone))
	}

	fn write_after_mutation(
		&self,
		mut state: Self::StateT,
		mut state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<Self::HashType> {
		state.prune_state_diff(); // Remove state diff before storing.
		let state_hash = state.hash();
		// We create a state copy here, in order to serve the state observer. This does not scale
		// well and we will want a better solution in the future, maybe with #459.
		state_lock.insert(*shard, (state.clone(), state_hash));
		drop(state_lock); // Drop the write lock as early as possible.

		self.update_state_snapshot(shard, &state, state_hash)?;

		self.state_observer.queue_state_update(*shard, state)?;
		Ok(state_hash)
	}

	fn reset(&self, state: Self::StateT, shard: &ShardIdentifier) -> Result<Self::HashType> {
		let state_write_lock = self.states_map_lock.write().map_err(|_| Error::LockPoisoning)?;
		self.write_after_mutation(state, state_write_lock, shard)
	}
}

impl<Repository, StateObserver, StateInitializer> QueryShardState
	for StateHandler<Repository, StateObserver, StateInitializer>
where
	Repository: VersionedStateAccess,
	Repository::StateType: Hash<Repository::HashType>,
	StateObserver: UpdateState<Repository::StateType>,
	StateInitializer: InitializeState<StateType = Repository::StateType>,
{
	fn shard_exists(&self, shard: &ShardIdentifier) -> Result<bool> {
		let states_map_lock = self.states_map_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(states_map_lock.contains_key(shard))
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		let states_map_lock = self.states_map_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(states_map_lock.keys().cloned().collect())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::mocks::{
		initialize_state_mock::InitializeStateMock,
		versioned_state_access_mock::VersionedStateAccessMock,
	};
	use codec::Encode;
	use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesType};
	use itp_stf_state_observer::mock::UpdateStateMock;
	use itp_types::H256;
	use std::{collections::VecDeque, sync::Arc, thread};

	type TestState = SgxExternalities;
	type TestHash = H256;
	type TestStateRepository = VersionedStateAccessMock<TestState, TestHash>;
	type TestStateObserver = UpdateStateMock<TestState>;
	type TestStateInitializer = InitializeStateMock<TestState>;
	type TestStateHandler =
		StateHandler<TestStateRepository, TestStateObserver, TestStateInitializer>;

	fn create_state(content: u64) -> TestState {
		let mut state = TestState::new(SgxExternalitiesType::default());
		state.insert("key_1".encode(), content.encode());
		state
	}

	fn create_state_without_diff(content: u64) -> TestState {
		let state = create_state(content);
		prune_diff(state)
	}

	fn prune_diff(mut state: TestState) -> TestState {
		state.prune_state_diff();
		state
	}

	#[test]
	fn load_for_mutation_blocks_any_concurrent_access() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler();
		state_handler.initialize_shard(shard_id).unwrap();

		let (lock, _s) = state_handler.load_for_mutation(&shard_id).unwrap();

		let state_handler_clone = state_handler.clone();
		let join_handle = thread::spawn(move || {
			let (latest_state, _) = state_handler_clone.load_cloned(&shard_id).unwrap();
			assert_eq!(create_state_without_diff(4u64), latest_state);
		});

		let _hash =
			state_handler.write_after_mutation(create_state(4u64), lock, &shard_id).unwrap();

		join_handle.join().unwrap();
	}

	#[test]
	fn write_and_reset_queue_observer_update() {
		let shard_id = ShardIdentifier::default();
		let state_observer = Arc::new(TestStateObserver::default());
		let state_initializer = Arc::new(TestStateInitializer::new(Default::default()));
		let state_handler = Arc::new(TestStateHandler::new(
			default_repository(),
			state_observer.clone(),
			state_initializer,
		));
		state_handler.initialize_shard(shard_id).unwrap();

		let (lock, _s) = state_handler.load_for_mutation(&shard_id).unwrap();
		let new_state = create_state(4u64);
		state_handler.write_after_mutation(new_state.clone(), lock, &shard_id).unwrap();

		let reset_state = create_state(5u64);
		state_handler.reset(reset_state.clone(), &shard_id).unwrap();

		let observer_updates = state_observer.queued_updates.read().unwrap().clone();
		assert_eq!(3, observer_updates.len());
		assert_eq!((shard_id, prune_diff(new_state)), observer_updates[1]);
		assert_eq!((shard_id, prune_diff(reset_state)), observer_updates[2]);
	}

	#[test]
	fn load_initialized_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler();
		state_handler.initialize_shard(shard_id).unwrap();
		assert!(state_handler.load_cloned(&shard_id).is_ok());
		assert!(state_handler.load_cloned(&ShardIdentifier::random()).is_err());
	}

	#[test]
	fn list_shards_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler();
		state_handler.initialize_shard(shard_id).unwrap();
		assert_eq!(1, state_handler.list_shards().unwrap().len());
	}

	#[test]
	fn shard_exists_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler();
		state_handler.initialize_shard(shard_id).unwrap();
		assert!(state_handler.shard_exists(&shard_id).unwrap());
		assert!(!state_handler.shard_exists(&ShardIdentifier::random()).unwrap());
	}

	#[test]
	fn load_from_repository_works() {
		let state_observer = Arc::new(TestStateObserver::default());
		let state_initializer = Arc::new(TestStateInitializer::new(Default::default()));

		let repository = TestStateRepository::new(HashMap::from([
			(
				ShardIdentifier::from([1u8; 32]),
				VecDeque::from([create_state(3), create_state(2), create_state(1)]),
			),
			(ShardIdentifier::from([2u8; 32]), VecDeque::from([create_state(5)])),
			(ShardIdentifier::from([3u8; 32]), VecDeque::new()),
		]));

		assert_eq!(3, repository.list_shards().unwrap().len());
		assert!(repository.load_latest(&ShardIdentifier::from([3u8; 32])).is_err());

		let state_handler =
			TestStateHandler::load_from_repository(repository, state_observer, state_initializer)
				.unwrap();

		assert_eq!(
			2,
			state_handler.list_shards().unwrap().len(),
			"Only 2 shards, not 3, because 3rd was empty"
		);
	}

	#[test]
	fn ensure_state_diff_is_discarded() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler();

		let state = create_state(3u64);
		let state_without_diff = {
			let mut state_clone = state.clone();
			state_clone.prune_state_diff();
			state_clone
		};

		state_handler.reset(state, &shard_id).unwrap();
		let (loaded_state, _) = state_handler.load_cloned(&shard_id).unwrap();

		assert_eq!(state_without_diff, loaded_state);
	}

	fn default_state_handler() -> Arc<TestStateHandler> {
		let state_observer = Arc::new(TestStateObserver::default());
		let state_initializer = Arc::new(TestStateInitializer::new(Default::default()));
		Arc::new(TestStateHandler::new(default_repository(), state_observer, state_initializer))
	}

	fn default_repository() -> TestStateRepository {
		TestStateRepository::default()
	}
}
