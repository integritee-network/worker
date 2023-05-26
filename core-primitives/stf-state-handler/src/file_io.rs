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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(any(test, feature = "std"))]
use rust_base58::base58::{FromBase58, ToBase58};

#[cfg(feature = "sgx")]
use base58::{FromBase58, ToBase58};

#[cfg(any(test, feature = "sgx"))]
use std::string::String;

use crate::{
	error::{Error, Result},
	state_snapshot_primitives::StateId,
};
use codec::{Decode, Encode};
use itp_settings::files::SHARDS_PATH;
use itp_types::ShardIdentifier;
use log::error;
use std::{
	format,
	path::{Path, PathBuf},
	vec::Vec,
};

/// Encrypted state file suffix
pub const ENCRYPTED_STATE_FILE: &str = "state.bin";

/// Helps with file system operations for all files relevant for the State.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StatePathHelper {
	base_path: PathBuf,
}

impl StatePathHelper {
	pub fn new(base_path: PathBuf) -> Self {
		Self { base_path }
	}

	pub fn shards_directory(&self) -> PathBuf {
		self.base_path.join(SHARDS_PATH)
	}

	pub fn shard_path(&self, shard: &ShardIdentifier) -> PathBuf {
		self.shards_directory().join(shard.encode().to_base58())
	}

	/// Lists any valid shards that are found in the shard path.
	///
	/// Ignores any items (files, directories) that are not valid shard identifiers.
	pub fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		list_shards(&self.shards_directory())
	}

	/// Lists all files with a valid state snapshot naming pattern.
	pub fn list_state_ids_for_shard(
		&self,
		shard_identifier: &ShardIdentifier,
	) -> Result<Vec<StateId>> {
		let shard_path = self.shard_path(shard_identifier);
		let directory_items = list_items_in_directory(&shard_path);

		Ok(directory_items
			.iter()
			.flat_map(|item| {
				let maybe_state_id = extract_state_id_from_file_name(item.as_str());
				if maybe_state_id.is_none() {
					log::warn!("Found item ({}) that does not match state snapshot naming pattern, ignoring it", item)
				}
				maybe_state_id
			})
			.collect())
	}

	pub fn purge_shard_dir(&self, shard: &ShardIdentifier) {
		let shard_dir_path = self.shard_path(shard);
		if let Err(e) = std::fs::remove_dir_all(&shard_dir_path) {
			error!("Failed to remove shard directory {:?}: {:?}", shard_dir_path, e);
		}
	}

	pub fn shard_exists(&self, shard: &ShardIdentifier) -> bool {
		let shard_path = self.shard_path(shard);
		if !shard_path.exists() {
			return false
		}

		shard_path
			.read_dir()
			// When the iterator over all files in the directory returns none, the directory is empty.
			.map(|mut d| d.next().is_some())
			.unwrap_or(false)
	}

	pub fn create_shard(&self, shard: &ShardIdentifier) -> Result<()> {
		std::fs::create_dir_all(self.shard_path(shard)).map_err(|e| Error::Other(e.into()))
	}

	pub fn state_file_path(&self, shard: &ShardIdentifier, state_id: StateId) -> PathBuf {
		self.shard_path(shard).join(to_file_name(state_id))
	}

	pub fn file_for_state_exists(&self, shard: &ShardIdentifier, state_id: StateId) -> bool {
		self.state_file_path(shard, state_id).exists()
	}
}

/// Trait to abstract file I/O for state.
pub trait StateFileIo {
	type StateType;
	type HashType;

	/// Load a state (returns error if it does not exist).
	fn load(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::StateType>;

	/// Compute the state hash of a specific state (returns error if it does not exist).
	///
	/// Requires loading and decoding of the state. Use only when loading the state repository on
	/// initialization of the worker. Computing the state hash in other cases is the
	/// StateHandler's responsibility.
	fn compute_hash(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
	) -> Result<Self::HashType>;

	/// Initialize a new shard with a given state.
	fn initialize_shard(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
		state: &Self::StateType,
	) -> Result<Self::HashType>;

	/// Write the state.
	fn write(
		&self,
		shard_identifier: &ShardIdentifier,
		state_id: StateId,
		state: &Self::StateType,
	) -> Result<Self::HashType>;

	/// Remove a state.
	fn remove(&self, shard_identifier: &ShardIdentifier, state_id: StateId) -> Result<()>;

	/// Checks if a given shard directory exists and contains at least one state instance.
	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool;

	/// Lists all shards.
	fn list_shards(&self) -> Result<Vec<ShardIdentifier>>;

	/// List all states for a shard.
	fn list_state_ids_for_shard(&self, shard_identifier: &ShardIdentifier) -> Result<Vec<StateId>>;
}

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use crate::error::Error;
	use codec::Decode;
	use core::fmt::Debug;
	use itp_hashing::Hash;
	use itp_sgx_crypto::{key_repository::AccessKey, StateCrypto};
	use itp_sgx_externalities::SgxExternalitiesTrait;
	use itp_sgx_io::{read as io_read, write as io_write};
	use itp_types::H256;
	use log::*;
	use std::{fs, marker::PhantomData, path::Path, sync::Arc};

	/// SGX state file I/O.
	pub struct SgxStateFileIo<StateKeyRepository, State> {
		state_key_repository: Arc<StateKeyRepository>,
		path_helper: StatePathHelper,
		_phantom: PhantomData<State>,
	}

	impl<StateKeyRepository, State> SgxStateFileIo<StateKeyRepository, State>
	where
		StateKeyRepository: AccessKey,
		<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
		State: SgxExternalitiesTrait,
	{
		pub fn new(
			state_key_repository: Arc<StateKeyRepository>,
			path_helper: StatePathHelper,
		) -> Self {
			SgxStateFileIo { state_key_repository, path_helper, _phantom: PhantomData }
		}

		fn read(&self, path: &Path) -> Result<Vec<u8>> {
			let mut bytes = io_read(path)?;

			if bytes.is_empty() {
				return Ok(bytes)
			}

			let state_key = self.state_key_repository.retrieve_key()?;

			state_key
				.decrypt(&mut bytes)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			trace!("buffer decrypted = {:?}", bytes);

			Ok(bytes)
		}

		fn encrypt(&self, mut state: Vec<u8>) -> Result<Vec<u8>> {
			let state_key = self.state_key_repository.retrieve_key()?;

			state_key
				.encrypt(&mut state)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(state)
		}
	}

	impl<StateKeyRepository, State> StateFileIo for SgxStateFileIo<StateKeyRepository, State>
	where
		StateKeyRepository: AccessKey,
		<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
		State: SgxExternalitiesTrait + Hash<H256> + Debug,
		<State as SgxExternalitiesTrait>::SgxExternalitiesType: Encode + Decode,
	{
		type StateType = State;
		type HashType = H256;

		fn load(
			&self,
			shard_identifier: &ShardIdentifier,
			state_id: StateId,
		) -> Result<Self::StateType> {
			if !self.path_helper.file_for_state_exists(shard_identifier, state_id) {
				return Err(Error::InvalidStateId(state_id))
			}

			let state_path = self.path_helper.state_file_path(shard_identifier, state_id);
			trace!("loading state from: {:?}", state_path);
			let state_encoded = self.read(&state_path)?;

			// State is now decrypted.
			debug!(
				"State loaded from {:?} with size {}B, deserializing...",
				state_path,
				state_encoded.len()
			);
			let state = <State as SgxExternalitiesTrait>::SgxExternalitiesType::decode(
				&mut state_encoded.as_slice(),
			)?;

			trace!("state decoded successfully");
			// Add empty state-diff.
			let state_with_diff = State::new(state);
			trace!("New state created: {:?}", state_with_diff);
			Ok(state_with_diff)
		}

		fn compute_hash(
			&self,
			shard_identifier: &ShardIdentifier,
			state_id: StateId,
		) -> Result<Self::HashType> {
			let state = self.load(shard_identifier, state_id)?;
			Ok(state.hash())
		}

		fn initialize_shard(
			&self,
			shard_identifier: &ShardIdentifier,
			state_id: StateId,
			state: &Self::StateType,
		) -> Result<Self::HashType> {
			self.path_helper.create_shard(&shard_identifier)?;
			self.write(shard_identifier, state_id, state)
		}

		/// Writes the state (without the state diff) encrypted into the enclave storage.
		/// Returns the hash of the saved state (independent of the diff!).
		fn write(
			&self,
			shard_identifier: &ShardIdentifier,
			state_id: StateId,
			state: &Self::StateType,
		) -> Result<Self::HashType> {
			let state_path = self.path_helper.state_file_path(shard_identifier, state_id);
			trace!("writing state to: {:?}", state_path);

			// Only save the state, the state diff is pruned.
			let cyphertext = self.encrypt(state.state().encode())?;

			let state_hash = state.hash();

			io_write(&cyphertext, &state_path)?;

			Ok(state_hash)
		}

		fn remove(&self, shard_identifier: &ShardIdentifier, state_id: StateId) -> Result<()> {
			fs::remove_file(self.path_helper.state_file_path(shard_identifier, state_id))
				.map_err(|e| Error::Other(e.into()))
		}

		fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
			self.path_helper.shard_exists(shard_identifier)
		}

		fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
			self.path_helper.list_shards()
		}

		fn list_state_ids_for_shard(&self, shard: &ShardIdentifier) -> Result<Vec<StateId>> {
			self.path_helper.list_state_ids_for_shard(shard)
		}
	}
}

pub(crate) fn list_shards(path: &Path) -> Result<Vec<ShardIdentifier>> {
	let directory_items = list_items_in_directory(path);
	Ok(directory_items
		.iter()
		.filter_map(|item| {
			item.from_base58().ok().and_then(|encoded_shard_id| {
				ShardIdentifier::decode(&mut encoded_shard_id.as_slice()).ok()
			})
		})
		.collect())
}

fn list_items_in_directory(directory: &Path) -> Vec<String> {
	let items = match directory.read_dir() {
		Ok(rd) => rd,
		Err(_) => return Vec::new(),
	};

	items
		.filter_map(|fr| fr.ok().and_then(|de| de.file_name().into_string().ok()))
		.collect()
}

fn to_file_name(state_id: StateId) -> String {
	format!("{}_{}", state_id, ENCRYPTED_STATE_FILE)
}

fn extract_state_id_from_file_name(file_name: &str) -> Option<StateId> {
	let state_id_str = file_name.strip_suffix(format!("_{}", ENCRYPTED_STATE_FILE).as_str())?;
	state_id_str.parse::<StateId>().ok()
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::state_snapshot_primitives::generate_current_timestamp_state_id;

	#[test]
	fn state_id_to_file_name_works() {
		assert!(to_file_name(generate_current_timestamp_state_id()).ends_with(ENCRYPTED_STATE_FILE));
		assert!(to_file_name(generate_current_timestamp_state_id())
			.strip_suffix(format!("_{}", ENCRYPTED_STATE_FILE).as_str())
			.is_some());

		let now_time_stamp = generate_current_timestamp_state_id();
		assert_eq!(
			extract_state_id_from_file_name(to_file_name(now_time_stamp).as_str()).unwrap(),
			now_time_stamp
		);
	}

	#[test]
	fn extract_timestamp_from_file_name_works() {
		assert_eq!(
			123456u128,
			extract_state_id_from_file_name(format!("123456_{}", ENCRYPTED_STATE_FILE).as_str())
				.unwrap()
		);
		assert_eq!(
			0u128,
			extract_state_id_from_file_name(format!("0_{}", ENCRYPTED_STATE_FILE).as_str())
				.unwrap()
		);

		assert!(extract_state_id_from_file_name(
			format!("987345{}", ENCRYPTED_STATE_FILE).as_str()
		)
		.is_none());
		assert!(
			extract_state_id_from_file_name(format!("{}", ENCRYPTED_STATE_FILE).as_str()).is_none()
		);
		assert!(extract_state_id_from_file_name(
			format!("1234_{}-other", ENCRYPTED_STATE_FILE).as_str()
		)
		.is_none());
	}
}
