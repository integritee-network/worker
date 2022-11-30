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
use itp_types::ShardIdentifier;

/// Facade for handling STF state loading and storing (e.g. from file).
pub trait HandleState {
	type WriteLockPayload;
	type StateT;
	type HashType;

	/// Initialize a new shard.
	///
	/// Initializes a default state for the shard and returns its hash.
	fn initialize_shard(&self, shard: ShardIdentifier) -> Result<Self::HashType>;

	/// Execute a function that acts (immutably) on the current state.
	///
	/// This allows access to the state, without any cloning.
	fn execute_on_current<E, R>(&self, shard: &ShardIdentifier, executing_function: E) -> Result<R>
	where
		E: FnOnce(&Self::StateT, Self::HashType) -> R;

	/// Load a clone of the current state for a given shard.
	///
	/// Requires the shard to exist and be initialized, otherwise returns an error.
	/// Because it results in a clone, prefer using `execute_on_current` whenever possible.
	fn load_cloned(&self, shard: &ShardIdentifier) -> Result<(Self::StateT, Self::HashType)>;

	/// Load the state in order to mutate it.
	///
	/// Returns a write lock to protect against any concurrent access as long as
	/// the lock is held. Finalize the operation by calling `write` and returning
	/// the lock again.
	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, Self::StateT)>;

	/// Writes the state (without the state diff) encrypted into the enclave.
	///
	/// Returns the hash of the saved state (independent of the diff!).
	fn write_after_mutation(
		&self,
		state: Self::StateT,
		state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<Self::HashType>;

	/// Reset (or override) a state.
	///
	/// Use in cases where the previous state is of no interest. Otherwise use `load_for_mutation` and `write_after_mutation`.
	fn reset(&self, state: Self::StateT, shard: &ShardIdentifier) -> Result<Self::HashType>;
}
