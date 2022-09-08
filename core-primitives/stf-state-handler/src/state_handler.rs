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
	state_snapshot_repository::VersionedStateAccess,
};
use itp_stf_state_observer::traits::UpdateState;
use itp_types::ShardIdentifier;
use std::{sync::Arc, vec::Vec};

/// Implementation of the `HandleState` trait.
///
/// It's a concurrency wrapper around a state snapshot repository, which handles
/// access to any shards and state files. The state handler ensures we have thread-safe
/// concurrent access to that repository.
pub struct StateHandler<Repository, StateObserver> {
	state_snapshot_repository: RwLock<Repository>,
	state_observer: Arc<StateObserver>,
}

impl<Repository, StateObserver> StateHandler<Repository, StateObserver> {
	pub fn new(state_snapshot_repository: Repository, state_observer: Arc<StateObserver>) -> Self {
		StateHandler {
			state_snapshot_repository: RwLock::new(state_snapshot_repository),
			state_observer,
		}
	}
}

impl<Repository, StateObserver> HandleState for StateHandler<Repository, StateObserver>
where
	Repository: VersionedStateAccess,
	StateObserver: UpdateState<Repository::StateType>,
{
	type WriteLockPayload = Repository;
	type StateT = Repository::StateType;
	type HashType = Repository::HashType;

	fn initialize_shard(&self, shard: ShardIdentifier) -> Result<Self::HashType> {
		let mut state_write_lock =
			self.state_snapshot_repository.write().map_err(|_| Error::LockPoisoning)?;
		state_write_lock.initialize_new_shard(shard)
	}

	fn load(&self, shard: &ShardIdentifier) -> Result<Self::StateT> {
		self.state_snapshot_repository
			.read()
			.map_err(|_| Error::LockPoisoning)?
			.load_latest(shard)
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, Self::StateT)> {
		let state_write_lock =
			self.state_snapshot_repository.write().map_err(|_| Error::LockPoisoning)?;
		let loaded_state = state_write_lock.load_latest(shard)?;
		Ok((state_write_lock, loaded_state))
	}

	fn write_after_mutation(
		&self,
		state: Self::StateT,
		mut state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<Self::HashType> {
		// We create a state copy here, in order to serve the state observer. This does not scale
		// well and we will want a better solution in the future, maybe with #459.
		let state_hash = state_lock.update(shard, state.clone())?;
		drop(state_lock); // Drop the write lock as early as possible.

		self.state_observer.queue_state_update(*shard, state)?;
		Ok(state_hash)
	}

	fn reset(&self, state: Self::StateT, shard: &ShardIdentifier) -> Result<Self::HashType> {
		let mut state_write_lock =
			self.state_snapshot_repository.write().map_err(|_| Error::LockPoisoning)?;

		// We create a state copy here, in order to serve the state observer. This does not scale
		// well and we will want a better solution in the future, maybe with #459.
		let state_hash = state_write_lock.update(shard, state.clone())?;
		drop(state_write_lock); // Drop the write lock as early as possible.

		self.state_observer.queue_state_update(*shard, state)?;
		Ok(state_hash)
	}
}

impl<Repository, StateObserver> QueryShardState for StateHandler<Repository, StateObserver>
where
	Repository: VersionedStateAccess,
{
	fn shard_exists(&self, shard: &ShardIdentifier) -> Result<bool> {
		let registry_lock =
			self.state_snapshot_repository.read().map_err(|_| Error::LockPoisoning)?;

		Ok(registry_lock.shard_exists(shard))
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		self.state_snapshot_repository
			.read()
			.map_err(|_| Error::LockPoisoning)?
			.list_shards()
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::test::mocks::versioned_state_access_mock::VersionedStateAccessMock;
	use itp_stf_state_observer::mock::UpdateStateMock;
	use std::{
		collections::{HashMap, VecDeque},
		sync::Arc,
		thread,
	};

	type TestState = u64;
	type TestHash = u64;
	type TestStateRepository = VersionedStateAccessMock<TestState, TestHash>;
	type TestStateObserver = UpdateStateMock<TestState>;
	type TestStateHandler = StateHandler<TestStateRepository, TestStateObserver>;

	#[test]
	fn load_for_mutation_blocks_any_concurrent_access() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler(&shard_id);

		let (lock, _s) = state_handler.load_for_mutation(&shard_id).unwrap();
		let new_state = 4u64;

		let state_handler_clone = state_handler.clone();
		let join_handle = thread::spawn(move || {
			let latest_state = state_handler_clone.load(&shard_id).unwrap();
			assert_eq!(new_state, latest_state);
		});

		let _hash = state_handler.write_after_mutation(new_state, lock, &shard_id).unwrap();

		join_handle.join().unwrap();
	}

	#[test]
	fn write_and_reset_queue_observer_update() {
		let shard_id = ShardIdentifier::default();
		let state_observer = Arc::new(TestStateObserver::default());
		let state_handler =
			Arc::new(TestStateHandler::new(default_repository(&shard_id), state_observer.clone()));

		let (lock, _s) = state_handler.load_for_mutation(&shard_id).unwrap();
		let new_state = 4u64;
		state_handler.write_after_mutation(new_state, lock, &shard_id).unwrap();

		let reset_state = 5u64;
		state_handler.reset(reset_state, &shard_id).unwrap();

		let observer_updates = state_observer.queued_updates.read().unwrap().clone();
		assert_eq!(2, observer_updates.len());
		assert_eq!((shard_id, new_state), observer_updates[0]);
		assert_eq!((shard_id, reset_state), observer_updates[1]);
	}

	#[test]
	fn load_initialized_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler(&shard_id);
		assert!(state_handler.load(&shard_id).is_ok());
		assert!(state_handler.load(&ShardIdentifier::random()).is_err());
	}

	#[test]
	fn list_shards_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler(&shard_id);
		assert!(state_handler.list_shards().is_ok());
	}

	#[test]
	fn shard_exists_works() {
		let shard_id = ShardIdentifier::random();
		let state_handler = default_state_handler(&shard_id);
		assert!(state_handler.shard_exists(&shard_id).unwrap());
		assert!(!state_handler.shard_exists(&ShardIdentifier::random()).unwrap());
	}

	fn default_state_handler(shard: &ShardIdentifier) -> Arc<TestStateHandler> {
		let state_observer = Arc::new(TestStateObserver::default());
		Arc::new(TestStateHandler::new(default_repository(shard), state_observer))
	}

	fn default_repository(shard: &ShardIdentifier) -> TestStateRepository {
		TestStateRepository::new(HashMap::from([(*shard, VecDeque::from([1, 2, 3]))]))
	}
}
