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

#[cfg(feature = "std")]
use rust_base58::base58::{FromBase58, ToBase58};

#[cfg(feature = "sgx")]
use base58::{FromBase58, ToBase58};

use crate::error::{Error, Result};
use codec::{Decode, Encode};
use itp_settings::files::SHARDS_PATH;
use itp_types::ShardIdentifier;
use log::error;
use std::{
	format, fs,
	path::{Path, PathBuf},
	string::String,
	vec::Vec,
};

/// Trait to abstract file I/O for state.
pub trait StateFileIo {
	type StateType;
	type HashType;

	/// Load a state file (returns error if it does not exist).
	fn load(&self, shard_identifier: &ShardIdentifier, file_name: &str) -> Result<Self::StateType>;

	/// Compute the state hash of a specific state file (returns error if it does not exist).
	fn compute_hash(
		&self,
		shard_identifier: &ShardIdentifier,
		file_name: &str,
	) -> Result<Self::HashType>;

	/// Create an empty (default initialized) state file.
	fn create_initialized(
		&self,
		shard_identifier: &ShardIdentifier,
		file_name: &str,
	) -> Result<Self::HashType>;

	/// Write the state to file.
	fn write(
		&self,
		shard_identifier: &ShardIdentifier,
		file_name: &str,
		state: Self::StateType,
	) -> Result<Self::HashType>;

	/// Remove a state file.
	fn remove(&self, shard_identifier: &ShardIdentifier, file_name: &str) -> Result<()>;

	/// Checks if a given shard directory exists and contains state files.
	fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool;

	/// Lists all shards.
	fn list_shards(&self) -> Result<Vec<ShardIdentifier>>;

	/// List all files for a shard.
	fn list_shard_files(&self, shard_identifier: &ShardIdentifier) -> Result<Vec<String>>;
}

#[cfg(feature = "sgx")]
pub mod sgx {

	use super::*;
	use ita_stf::{State as StfState, StateType as StfStateType, Stf};
	use itp_sgx_crypto::StateCrypto;
	use itp_sgx_io::{read as io_read, write as io_write};
	use itp_types::H256;
	use log::*;
	use sgx_tcrypto::rsgx_sha256_slice;
	use std::{path::Path, string::ToString};

	/// SGX state file I/O
	pub struct SgxStateFileIo<StateKey> {
		state_key: StateKey,
	}

	impl<StateKey> SgxStateFileIo<StateKey>
	where
		StateKey: StateCrypto<Error = itp_sgx_crypto::Error>,
	{
		pub fn new(state_key: StateKey) -> Self {
			SgxStateFileIo { state_key }
		}

		fn read(&self, path: &Path) -> Result<Vec<u8>> {
			let mut bytes = io_read(path)?;

			if bytes.is_empty() {
				return Ok(bytes)
			}

			let state_hash = rsgx_sha256_slice(&bytes)?;
			debug!(
				"read encrypted state with hash {:?} from {:?}",
				H256::from_slice(state_hash.as_ref()),
				path
			);

			self.state_key.decrypt(&mut bytes).map_err(Error::CryptoError)?;
			trace!("buffer decrypted = {:?}", bytes);

			Ok(bytes)
		}

		fn encrypt(&self, mut state: Vec<u8>) -> Result<Vec<u8>> {
			self.state_key.encrypt(&mut state).map_err(Error::CryptoError)?;
			Ok(state)
		}
	}

	impl<StateKey> StateFileIo for SgxStateFileIo<StateKey>
	where
		StateKey: StateCrypto<Error = itp_sgx_crypto::Error>,
	{
		type StateType = StfState;
		type HashType = H256;

		fn load(
			&self,
			shard_identifier: &ShardIdentifier,
			file_name: &str,
		) -> Result<Self::StateType> {
			if !state_file_exists(shard_identifier, file_name) {
				return Err(Error::InvalidStateFile(file_name.to_string()))
			}

			let state_path = state_file_path(shard_identifier, file_name);
			trace!("loading state from: {:?}", state_path);
			let state_vec = self.read(&state_path)?;

			// state is now decrypted!
			let state: StfStateType = match state_vec.len() {
				0 => {
					debug!("state at {:?} is empty. will initialize it.", state_path);
					Stf::init_state().state
				},
				n => {
					debug!("State loaded from {:?} with size {}B, deserializing...", state_path, n);
					StfStateType::decode(&mut state_vec.as_slice())?
				},
			};
			trace!("state decoded successfully");
			// add empty state-diff
			let state_with_diff = StfState { state, state_diff: Default::default() };
			trace!("New state created: {:?}", state_with_diff);
			Ok(state_with_diff)
		}

		fn compute_hash(
			&self,
			shard_identifier: &ShardIdentifier,
			file_name: &str,
		) -> Result<Self::HashType> {
			if !state_file_exists(shard_identifier, file_name) {
				return Err(Error::InvalidStateFile(file_name.to_string()))
			}

			let state_file_path = state_file_path(shard_identifier, file_name);
			let bytes = io_read(state_file_path)?;
			let state_hash = rsgx_sha256_slice(&bytes)?;
			Ok(H256::from_slice(state_hash.as_ref()))
		}

		fn create_initialized(
			&self,
			shard_identifier: &ShardIdentifier,
			file_name: &str,
		) -> Result<Self::HashType> {
			init_shard(&shard_identifier)?;
			let state = Stf::init_state();
			self.write(shard_identifier, file_name, state)
		}

		/// Writes the state (without the state diff) encrypted into the enclave storage
		/// Returns the hash of the saved state (independent of the diff!)
		fn write(
			&self,
			shard_identifier: &ShardIdentifier,
			file_name: &str,
			state: Self::StateType,
		) -> Result<Self::HashType> {
			let state_path = state_file_path(shard_identifier, file_name);
			trace!("writing state to: {:?}", state_path);

			// only save the state, the state diff is pruned
			let cyphertext = self.encrypt(state.state.encode())?;

			let state_hash = rsgx_sha256_slice(&cyphertext)?;

			debug!("new encrypted state with hash={:?} written to {:?}", state_hash, state_path);

			io_write(&cyphertext, &state_path)?;
			Ok(state_hash.into())
		}

		fn remove(&self, shard_identifier: &ShardIdentifier, file_name: &str) -> Result<()> {
			fs::remove_file(state_file_path(shard_identifier, file_name))
				.map_err(|e| Error::Other(e.into()))
		}

		fn shard_exists(&self, shard_identifier: &ShardIdentifier) -> bool {
			shard_exists(shard_identifier)
		}

		fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
			list_shards()
		}

		fn list_shard_files(&self, shard_identifier: &ShardIdentifier) -> Result<Vec<String>> {
			let shard_path = shard_path(shard_identifier);
			Ok(list_items_in_directory(&shard_path))
		}
	}
}

/// Remove a shard directory with all of its content.
pub fn remove_shard_dir(shard: &ShardIdentifier) {
	let shard_dir_path = shard_path(shard);
	if let Err(e) = std::fs::remove_dir_all(&shard_dir_path) {
		error!("Failed to remove shard directory {:?}: {:?}", shard_dir_path, e);
	}
}

pub(crate) fn state_file_path(shard: &ShardIdentifier, file_name: &str) -> PathBuf {
	let mut shard_file_path = shard_path(shard);
	shard_file_path.push(file_name);
	shard_file_path
}

pub(crate) fn shard_path(shard: &ShardIdentifier) -> PathBuf {
	PathBuf::from(format!("{}/{}", SHARDS_PATH, shard.encode().to_base58()))
}

#[allow(unused)]
fn state_file_exists(shard: &ShardIdentifier, file_name: &str) -> bool {
	state_file_path(shard, file_name).exists()
}

#[allow(unused)]
pub(crate) fn shard_exists(shard: &ShardIdentifier) -> bool {
	let shard_path = shard_path(shard);
	if !shard_path.exists() {
		return false
	}

	shard_path
		.read_dir()
		// when the iterator over all files in the directory returns none, the directory is empty
		.map(|mut d| d.next().is_some())
		.unwrap_or(false)
}

#[allow(unused)]
pub(crate) fn init_shard(shard: &ShardIdentifier) -> Result<()> {
	let path = shard_path(shard);
	fs::create_dir_all(path).map_err(|e| Error::Other(e.into()))
}

fn list_items_in_directory(directory: &Path) -> Vec<String> {
	let items = match directory.read_dir() {
		Ok(rd) => rd,
		Err(_) => return Vec::new(),
	};

	items
		.flat_map(|fr| fr.map(|de| de.file_name().into_string().ok()).ok().flatten())
		.collect()
}

#[allow(unused)]
pub(crate) fn list_shards() -> Result<Vec<ShardIdentifier>> {
	let directory_items = list_items_in_directory(&PathBuf::from(SHARDS_PATH));
	let mut shards = Vec::new();
	for item in directory_items {
		let shard_encoded = item.from_base58()?;
		shards.push(ShardIdentifier::decode(&mut shard_encoded.as_slice())?);
	}
	Ok(shards)
}
