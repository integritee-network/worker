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
	state_snapshot_repository::VersionedStateAccess,
};
use itp_types::ShardIdentifier;
use std::{
	collections::{HashMap, VecDeque},
	marker::PhantomData,
	string::ToString,
	vec::Vec,
};

#[derive(Default, Clone)]
pub struct VersionedStateAccessMock<State, Hash> {
	state_history: HashMap<ShardIdentifier, VecDeque<State>>,
	phantom_data: PhantomData<Hash>,
}

impl<State, Hash> VersionedStateAccessMock<State, Hash> {
	#[cfg(test)]
	pub fn new(state_history: HashMap<ShardIdentifier, VecDeque<State>>) -> Self {
		VersionedStateAccessMock { state_history, phantom_data: Default::default() }
	}
}

impl<State, Hash> VersionedStateAccess for VersionedStateAccessMock<State, Hash>
where
	State: Default + Clone,
	Hash: Default,
{
	type StateType = State;
	type HashType = Hash;

	fn load_latest(&self, shard_identifier: &ShardIdentifier) -> Result<Self::StateType> {
		self.state_history
			.get(shard_identifier)
			.ok_or(Error::InvalidShard(*shard_identifier))?
			.front()
			.cloned()
			.ok_or(Error::StateNotFoundInRepository("".to_string()))
	}

	fn update(
		&mut self,
		shard_identifier: &ShardIdentifier,
		state: &Self::StateType,
		_state_hash: Self::HashType,
	) -> Result<()> {
		let state_history = self
			.state_history
			.entry(*shard_identifier)
			.or_insert_with(|| VecDeque::default());
		state_history.push_front(state.clone());
		Ok(())
	}

	fn revert_to(
		&mut self,
		shard_identifier: &ShardIdentifier,
		_state_hash: &Self::HashType,
	) -> Result<Self::StateType> {
		let state_history = self
			.state_history
			.get_mut(shard_identifier)
			.ok_or_else(|| Error::InvalidShard(*shard_identifier))?;
		state_history.drain(..).last().ok_or(Error::EmptyRepository)
	}

	fn initialize_new_shard(
		&mut self,
		shard_identifier: ShardIdentifier,
		state: &Self::StateType,
	) -> Result<Self::HashType> {
		self.state_history.insert(shard_identifier, VecDeque::from([state.clone()]));
		Ok(Hash::default())
	}

	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
		self.state_history.get(shard_identifier).is_some()
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.state_history.keys().copied().collect())
	}
}
