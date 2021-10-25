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
	file_io::{exists, list_shards, load_initialized_state, write as state_write},
	handle_state::HandleState,
	query_shard_state::QueryShardState,
};
use ita_stf::State as StfState;
use itp_types::{ShardIdentifier, H256};
use lazy_static::lazy_static;
use std::{
	sync::{SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard},
	vec::Vec,
};

lazy_static! {
	// as long as we have a file backend, we use this 'dummy' lock,
	// which guards against concurrent read/write access
	pub static ref STF_STATE_LOCK: RwLock<()> = Default::default();
}

/// Implementation of the `HandleState` trait using global files and locks.
///
/// For each call it will make a file access and encrypt/decrypt the state from file I/O.
/// The lock it uses is therefore an 'empty' dummy lock, that guards against concurrent file access.
pub struct GlobalFileStateHandler;

impl HandleState for GlobalFileStateHandler {
	type WriteLockPayload = ();

	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<StfState> {
		let _state_read_lock = STF_STATE_LOCK.read().map_err(|_| Error::LockPoisoning)?;
		load_initialized_state(shard)
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)> {
		let state_write_lock = STF_STATE_LOCK.write().map_err(|_| Error::LockPoisoning)?;
		let loaded_state = load_initialized_state(shard)?;
		Ok((state_write_lock, loaded_state))
	}

	fn write(
		&self,
		state: StfState,
		_state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256> {
		state_write(state, shard)
	}
}

impl QueryShardState for GlobalFileStateHandler {
	fn exists(&self, shard: &ShardIdentifier) -> bool {
		exists(shard)
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		list_shards()
	}
}
