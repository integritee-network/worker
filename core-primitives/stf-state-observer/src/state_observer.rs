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
	traits::{ObserveState, UpdateState},
};
use itp_types::ShardIdentifier;
use std::{collections::HashMap, vec::Vec};

/// State observer implementation. Receives updates in a dedicated queue.
/// These updates are applied every time an observation function is executed.
///
#[derive(Default)]
pub struct StateObserver<StateType> {
	queued_state_updates: RwLock<HashMap<ShardIdentifier, StateType>>,
	current_state: RwLock<HashMap<ShardIdentifier, StateType>>,
}

impl<StateType> StateObserver<StateType> {
	pub fn new(shard: ShardIdentifier, state: StateType) -> Self {
		Self {
			queued_state_updates: Default::default(),
			current_state: RwLock::new(HashMap::from([(shard, state)])),
		}
	}

	pub fn from_map(states_map: HashMap<ShardIdentifier, StateType>) -> Self {
		Self { queued_state_updates: Default::default(), current_state: RwLock::new(states_map) }
	}

	fn apply_pending_update(&self) -> Result<()> {
		let mut update_queue_lock =
			self.queued_state_updates.write().map_err(|_| Error::LockPoisoning)?;

		let state_updates: Vec<_> = update_queue_lock.drain().collect();
		drop(update_queue_lock);

		if !state_updates.is_empty() {
			let mut current_state_lock =
				self.current_state.write().map_err(|_| Error::LockPoisoning)?;
			for state_update in state_updates.into_iter() {
				current_state_lock.insert(state_update.0, state_update.1);
			}
			drop(current_state_lock);
		}

		Ok(())
	}
}

impl<StateType> ObserveState for StateObserver<StateType> {
	type StateType = StateType;

	fn observe_state<F, R>(&self, shard: &ShardIdentifier, observation_func: F) -> Result<R>
	where
		F: FnOnce(&mut Self::StateType) -> R,
	{
		// Check if there is a pending update and apply it.
		self.apply_pending_update()?;

		// Execute the observation function.
		let mut current_state_map_lock =
			self.current_state.write().map_err(|_| Error::LockPoisoning)?;

		match current_state_map_lock.get_mut(shard) {
			Some(s) => Ok(observation_func(s)),
			None => Err(Error::CurrentStateEmpty),
		}
	}
}

impl<StateType> UpdateState<StateType> for StateObserver<StateType> {
	fn queue_state_update(&self, shard: ShardIdentifier, state: StateType) -> Result<()> {
		let mut update_queue_lock =
			self.queued_state_updates.write().map_err(|_| Error::LockPoisoning)?;
		update_queue_lock.insert(shard, state);
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;

	type TestState = u64;

	#[test]
	fn default_constructs_empty_state() {
		let state_observer = StateObserver::<TestState>::default();

		assert_matches!(
			state_observer.observe_state(&shard(), |_| { () }),
			Err(Error::CurrentStateEmpty)
		);
	}

	#[test]
	fn initializing_state_with_some_works() {
		let state_observer = StateObserver::<TestState>::new(shard(), 31u64);
		assert_eq!(state_observer.observe_state(&shard(), |s| *s).unwrap(), 31u64);
	}

	#[test]
	fn observing_multiple_times_after_update_works() {
		let state_observer = StateObserver::<TestState>::default();

		state_observer.queue_state_update(shard(), 42u64).unwrap();

		assert_eq!(state_observer.observe_state(&shard(), |s| *s).unwrap(), 42u64);
		assert_eq!(state_observer.observe_state(&shard(), |s| *s).unwrap(), 42u64);
		assert_eq!(state_observer.observe_state(&shard(), |s| *s).unwrap(), 42u64);
	}

	#[test]
	fn updating_multiple_times_before_observation_just_keeps_last_value() {
		let state_observer = StateObserver::<TestState>::new(shard(), 31);
		state_observer.queue_state_update(shard(), 42u64).unwrap();
		state_observer.queue_state_update(shard(), 57u64).unwrap();
		assert_eq!(1, state_observer.queued_state_updates.read().unwrap().len());
		assert_eq!(state_observer.observe_state(&shard(), |s| *s).unwrap(), 57u64);
	}

	fn shard() -> ShardIdentifier {
		ShardIdentifier::default()
	}
}
