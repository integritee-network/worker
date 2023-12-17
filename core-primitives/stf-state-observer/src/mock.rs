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
use core::fmt::Debug;
use itp_types::ShardIdentifier;
use log::*;
use std::vec::Vec;

/// Observe state mock.
#[derive(Default)]
pub struct ObserveStateMock<StateType> {
	state: RwLock<Option<StateType>>,
}

impl<StateType> ObserveStateMock<StateType> {
	pub fn new(state: StateType) -> Self {
		Self { state: RwLock::new(Some(state)) }
	}
}

impl<StateType> ObserveState for ObserveStateMock<StateType>
where
	StateType: Debug,
{
	type StateType = StateType;

	fn observe_state<F, R>(&self, _shard: &ShardIdentifier, observation_func: F) -> Result<R>
	where
		F: FnOnce(&mut Self::StateType) -> R,
	{
		let mut maybe_state_lock = self.state.write().unwrap();

		match &mut *maybe_state_lock {
			Some(state) => {
				debug!("State value: {:?}", state);
				Ok(observation_func(state))
			},
			None => Err(Error::CurrentShardStateEmpty),
		}
	}
}

/// Update state mock.
#[derive(Default)]
pub struct UpdateStateMock<StateType> {
	pub queued_updates: RwLock<Vec<(ShardIdentifier, StateType)>>,
}

impl<StateType> UpdateState<StateType> for UpdateStateMock<StateType> {
	fn queue_state_update(&self, shard: ShardIdentifier, state: StateType) -> Result<()> {
		let mut updates_lock = self.queued_updates.write().unwrap();
		updates_lock.push((shard, state));
		Ok(())
	}
}
