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

use crate::{error::Result, file_io::StateFileIo};
use itp_time_utils::now_as_nanos;
use itp_types::ShardIdentifier;
use std::collections::{HashMap, VecDeque};

pub type StateId = u128;

pub(crate) type SnapshotHistory<HashType> =
	HashMap<ShardIdentifier, VecDeque<StateSnapshotMetaData<HashType>>>;

/// Internal wrapper for a state hash and state ID.
#[derive(Clone)]
pub(crate) struct StateSnapshotMetaData<HashType> {
	pub(crate) state_hash: HashType,
	pub(crate) state_id: StateId,
}

impl<HashType> StateSnapshotMetaData<HashType> {
	pub fn new(state_hash: HashType, state_id: StateId) -> Self {
		StateSnapshotMetaData { state_hash, state_id }
	}
}

pub(crate) fn initialize_shard_with_snapshot<HashType, FileIo>(
	shard_identifier: &ShardIdentifier,
	file_io: &FileIo,
	state: &FileIo::StateType,
) -> Result<StateSnapshotMetaData<HashType>>
where
	FileIo: StateFileIo<HashType = HashType>,
{
	let state_id = generate_current_timestamp_state_id();
	let state_hash = file_io.initialize_shard(shard_identifier, state_id, state)?;
	Ok(StateSnapshotMetaData::new(state_hash, state_id))
}

pub(crate) fn generate_current_timestamp_state_id() -> StateId {
	now_as_nanos()
}
