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
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;

use crate::error::Result;
use itp_types::{ShardIdentifier, H256};

/// Facade for handling STF state loading and storing (e.g. from file)
pub trait HandleState {
	type WriteLockPayload;
	type StateT;

	/// Load the state for a given shard
	///
	/// Initializes the shard and state if necessary, so this is guaranteed to
	/// return a state
	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<Self::StateT>;

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, Self::StateT)>;

	/// Writes the state (without the state diff) encrypted into the enclave
	///
	/// Returns the hash of the saved state (independent of the diff!)
	fn write(
		&self,
		state: Self::StateT,
		state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256>;
}
