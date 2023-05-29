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

use crate::{error::Result, state_snapshot_primitives::StateId};
use codec::{Decode, Encode};
// Todo: Can be migrated to here in the course of #1292.
use itp_settings::files::SHARDS_PATH;
use itp_types::ShardIdentifier;
use log::error;
use std::{
	format,
	path::{Path, PathBuf},
	vec::Vec,
};

/// File name of the encrypted state file.
///
/// It is also the suffix of all past snapshots.
pub const ENCRYPTED_STATE_FILE: &str = "state.bin";

/// Helps with file system operations of all files relevant for the State.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StateDir {
	base_path: PathBuf,
}

impl StateDir {
	pub fn new(base_path: PathBuf) -> Self {
		Self { base_path }
	}

	pub fn shards_directory(&self) -> PathBuf {
		self.base_path.join(SHARDS_PATH)
	}

	pub fn shard_path(&self, shard: &ShardIdentifier) -> PathBuf {
		self.shards_directory().join(shard.encode().to_base58())
	}

	pub fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(list_shards(&self.shards_directory())
			.map(|iter| iter.collect())
			// return an empty vec in case the directory does not exist.
			.unwrap_or_default())
	}

	pub fn list_state_ids_for_shard(
		&self,
		shard_identifier: &ShardIdentifier,
	) -> Result<Vec<StateId>> {
		let shard_path = self.shard_path(shard_identifier);
		Ok(state_ids_for_shard(shard_path.as_path())?.collect())
	}

	pub fn purge_shard_dir(&self, shard: &ShardIdentifier) {
		let shard_dir_path = self.shard_path(shard);
		if let Err(e) = std::fs::remove_dir_all(&shard_dir_path) {
			error!("Failed to remove shard directory {:?}: {:?}", shard_dir_path, e);
		}
	}

	pub fn shard_exists(&self, shard: &ShardIdentifier) -> bool {
		let shard_path = self.shard_path(shard);
		shard_path.exists() && shard_contains_valid_state_id(&shard_path)
	}

	pub fn create_shard(&self, shard: &ShardIdentifier) -> Result<()> {
		Ok(std::fs::create_dir_all(self.shard_path(shard))?)
	}

	pub fn state_file_path(&self, shard: &ShardIdentifier, state_id: StateId) -> PathBuf {
		self.shard_path(shard).join(to_file_name(state_id))
	}

	pub fn file_for_state_exists(&self, shard: &ShardIdentifier, state_id: StateId) -> bool {
		self.state_file_path(shard, state_id).exists()
	}

	#[cfg(feature = "test")]
	pub fn given_initialized_shard(&self, shard: &ShardIdentifier) {
		if self.shard_exists(shard) {
			self.purge_shard_dir(shard);
		}
		self.create_shard(&shard).unwrap()
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
		state_dir: StateDir,
		_phantom: PhantomData<State>,
	}

	impl<StateKeyRepository, State> SgxStateFileIo<StateKeyRepository, State>
	where
		StateKeyRepository: AccessKey,
		<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
		State: SgxExternalitiesTrait,
	{
		pub fn new(state_key_repository: Arc<StateKeyRepository>, state_dir: StateDir) -> Self {
			SgxStateFileIo { state_key_repository, state_dir, _phantom: PhantomData }
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
			if !self.state_dir.file_for_state_exists(shard_identifier, state_id) {
				return Err(Error::InvalidStateId(state_id))
			}

			let state_path = self.state_dir.state_file_path(shard_identifier, state_id);
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
			self.state_dir.create_shard(&shard_identifier)?;
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
			let state_path = self.state_dir.state_file_path(shard_identifier, state_id);
			trace!("writing state to: {:?}", state_path);

			// Only save the state, the state diff is pruned.
			let cyphertext = self.encrypt(state.state().encode())?;

			let state_hash = state.hash();

			io_write(&cyphertext, &state_path)?;

			Ok(state_hash)
		}

		fn remove(&self, shard_identifier: &ShardIdentifier, state_id: StateId) -> Result<()> {
			Ok(fs::remove_file(self.state_dir.state_file_path(shard_identifier, state_id))?)
		}

		fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
			self.state_dir.shard_exists(shard_identifier)
		}

		fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
			self.state_dir.list_shards()
		}

		fn list_state_ids_for_shard(&self, shard: &ShardIdentifier) -> Result<Vec<StateId>> {
			self.state_dir.list_state_ids_for_shard(shard)
		}
	}
}

/// Lists all files with a valid state snapshot naming pattern.
pub(crate) fn state_ids_for_shard(shard_path: &Path) -> Result<impl Iterator<Item = StateId>> {
	Ok(items_in_directory(shard_path)?.filter_map(|item| {
		match extract_state_id_from_file_name(&item) {
			Some(state_id) => Some(state_id),
			None => {
				log::warn!(
				"Found item ({}) that does not match state snapshot naming pattern, ignoring it",
				item
			);
				None
			},
		}
	}))
}

/// Returns an iterator over all valid shards in a directory.
///
/// Ignore any items (files, directories) that are not valid shard identifiers.
pub(crate) fn list_shards(path: &Path) -> Result<impl Iterator<Item = ShardIdentifier>> {
	Ok(items_in_directory(path)?.filter_map(|base58| match shard_from_base58(&base58) {
		Ok(shard) => Some(shard),
		Err(e) => {
			error!("Found invalid shard ({}). Error: {:?}", base58, e);
			None
		},
	}))
}

fn shard_from_base58(base58: &str) -> Result<ShardIdentifier> {
	let vec = base58.from_base58()?;
	Ok(Decode::decode(&mut vec.as_slice())?)
}

/// Returns an iterator over all filenames in a directory.
fn items_in_directory(directory: &Path) -> Result<impl Iterator<Item = String>> {
	Ok(directory
		.read_dir()?
		.filter_map(|fr| fr.ok().and_then(|de| de.file_name().into_string().ok())))
}

fn shard_contains_valid_state_id(path: &Path) -> bool {
	// If at least on item can be decoded into a state id, the shard is not empty.
	match state_ids_for_shard(path) {
		Ok(mut iter) => iter.next().is_some(),
		Err(e) => {
			error!("Error in reading shard dir: {:?}", e);
			false
		},
	}
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
