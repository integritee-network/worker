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
use itp_settings::files::ENCRYPTED_STATE_FILE;
use itp_time_utils::now_as_nanos;
use itp_types::ShardIdentifier;
use std::{
	collections::{HashMap, VecDeque},
	format,
	string::String,
};

pub(crate) type SnapshotHistory<HashType> =
	HashMap<ShardIdentifier, VecDeque<StateFileMetaData<HashType>>>;

/// Internal wrapper for a state hash and file name.
#[derive(Clone)]
pub(crate) struct StateFileMetaData<HashType> {
	pub(crate) state_hash: HashType,
	pub(crate) file_name: String,
}

impl<HashType> StateFileMetaData<HashType> {
	pub fn new(state_hash: HashType, file_name: String) -> Self {
		StateFileMetaData { state_hash, file_name }
	}
}

pub(crate) fn initialize_shard_with_file<HashType, FileIo>(
	shard_identifier: &ShardIdentifier,
	file_io: &FileIo,
) -> Result<StateFileMetaData<HashType>>
where
	FileIo: StateFileIo<HashType = HashType>,
{
	let file_name = generate_current_timestamp_file_name();
	let state_hash = file_io.create_initialized(shard_identifier, file_name.as_str())?;
	Ok(StateFileMetaData::new(state_hash, file_name))
}

pub(crate) fn generate_current_timestamp_file_name() -> String {
	generate_file_name_from_timestamp(now_as_nanos())
}

pub(crate) fn generate_file_name_from_timestamp(timestamp: u128) -> String {
	format!("{}_{}", timestamp, ENCRYPTED_STATE_FILE)
}

pub(crate) fn extract_timestamp_from_file_name(file_name: &str) -> Option<u128> {
	let timestamp_str = file_name.strip_suffix(format!("_{}", ENCRYPTED_STATE_FILE).as_str())?;
	timestamp_str.parse::<u128>().ok()
}

#[cfg(test)]
mod tests {

	use super::*;
	use itp_settings::files::ENCRYPTED_STATE_FILE;

	#[test]
	fn generate_current_timestamp_file_names_works() {
		assert!(generate_current_timestamp_file_name().ends_with(ENCRYPTED_STATE_FILE));
		assert!(generate_current_timestamp_file_name()
			.strip_suffix(format!("_{}", ENCRYPTED_STATE_FILE).as_str())
			.is_some());
	}

	#[test]
	fn extract_timestamp_from_file_name_works() {
		assert_eq!(
			123456u128,
			extract_timestamp_from_file_name(format!("123456_{}", ENCRYPTED_STATE_FILE).as_str())
				.unwrap()
		);
		assert_eq!(
			0u128,
			extract_timestamp_from_file_name(format!("0_{}", ENCRYPTED_STATE_FILE).as_str())
				.unwrap()
		);

		assert!(extract_timestamp_from_file_name(
			format!("987345{}", ENCRYPTED_STATE_FILE).as_str()
		)
		.is_none());
		assert!(extract_timestamp_from_file_name(format!("{}", ENCRYPTED_STATE_FILE).as_str())
			.is_none());
		assert!(extract_timestamp_from_file_name(
			format!("1234_{}-other", ENCRYPTED_STATE_FILE).as_str()
		)
		.is_none());
	}
}
