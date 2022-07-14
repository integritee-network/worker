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

use crate::error::Result;
use itp_types::ShardIdentifier;
use std::vec::Vec;

/// Trait for querying shard information on the state
///
/// The reason this is a separate trait, is that it does not require any
/// SGX exclusive data structures (feature sgx)
pub trait QueryShardState {
	/// Query whether a given shard exists
	fn shard_exists(&self, shard: &ShardIdentifier) -> Result<bool>;

	/// List all available shards
	fn list_shards(&self) -> Result<Vec<ShardIdentifier>>;
}
