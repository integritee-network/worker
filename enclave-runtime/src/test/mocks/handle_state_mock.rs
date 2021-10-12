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
	state::HandleState,
};
use ita_stf::{ShardIdentifier, State as StfState};
use itp_types::H256;
use sgx_externalities::SgxExternalitiesTrait;
use std::{collections::HashMap, string::ToString, vec::Vec};

/// Mock implementation for the `HandleState` trait
///
/// To be used in unit tests
pub struct HandleStateMock {
	state_map: HashMap<ShardIdentifier, StfState>,
}

impl Default for HandleStateMock {
	fn default() -> Self {
		HandleStateMock { state_map: Default::default() }
	}
}

impl HandleState for HandleStateMock {
	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<StfState> {
		self.state_map
			.get(shard)
			.map(|s| s.clone())
			.ok_or_else(|| Error::Stf("No state for this shard exists".to_string()))
	}

	fn write(&mut self, state: StfState, shard: ShardIdentifier) -> Result<H256> {
		self.state_map.insert(shard, state);
		Ok(H256::default())
	}

	fn exists(&self, shard: &ShardIdentifier) -> bool {
		self.state_map.get(shard).is_some()
	}

	fn init_shard(&mut self, shard: &ShardIdentifier) -> Result<()> {
		self.state_map.insert(shard.clone(), StfState::new());
		Ok(())
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.state_map.iter().map(|(k, _)| k.clone()).collect())
	}
}
