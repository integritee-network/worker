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
	utils::UnwrapOrSgxErrorUnexpected,
};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use ita_stf::{ShardIdentifier, State as StfState, StateType as StfStateType, Stf};
use itp_settings::files::{ENCRYPTED_STATE_FILE, SHARDS_PATH};
use itp_sgx_crypto::{AesSeal, StateCrypto};
use itp_sgx_io::{read as io_read, write as io_write, SealedIO};
use lazy_static::lazy_static;
use log::*;
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::*;
use sp_core::H256;
use std::{
	fs,
	io::Write,
	path::Path,
	sync::{SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard},
	vec::Vec,
};

/// Facade for handling STF state from file
pub trait HandleState {
	type WriteLockPayload;

	/// Load the state for a given shard
	///
	/// Initializes the shard and state if necessary, so this is guaranteed to
	/// return a state
	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<StfState>;

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)>;

	/// Writes the state (without the state diff) encrypted into the enclave
	///
	/// Returns the hash of the saved state (independent of the diff!)
	fn write(
		&self,
		state: StfState,
		state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256>;

	/// Query whether a given shard exists
	fn exists(&self, shard: &ShardIdentifier) -> bool;

	/// List all available shards
	fn list_shards(&self) -> Result<Vec<ShardIdentifier>>;
}

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
		let _state_read_lock = STF_STATE_LOCK.read().map_err(|e| Error::Other(e.into()))?;
		load_initialized_state(shard)
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)> {
		let state_write_lock = STF_STATE_LOCK.write().map_err(|e| Error::Other(e.into()))?;
		let loaded_state = load_initialized_state(shard)?;
		Ok((state_write_lock, loaded_state))
	}

	fn write(
		&self,
		state: StfState,
		_state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256> {
		write(state, shard)
	}

	fn exists(&self, shard: &ShardIdentifier) -> bool {
		exists(shard)
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		list_shards()
	}
}

fn load_initialized_state(shard: &ShardIdentifier) -> Result<StfState> {
	trace!("Loading state from shard {:?}", shard);
	let state = if exists(&shard) {
		load(&shard)?
	} else {
		trace!("Initialize new shard: {:?}", shard);
		init_shard(&shard)?;
		Stf::init_state()
	};
	trace!("Successfully loaded or initialized state from shard {:?}", shard);
	Ok(state)
}

fn load(shard: &ShardIdentifier) -> Result<StfState> {
	// load last state
	let state_path =
		format!("{}/{}/{}", SHARDS_PATH, shard.encode().to_base58(), ENCRYPTED_STATE_FILE);
	trace!("loading state from: {}", state_path);
	let state_vec = read(&state_path)?;

	// state is now decrypted!
	let state: StfStateType = match state_vec.len() {
		0 => {
			debug!("state at {} is empty. will initialize it.", state_path);
			Stf::init_state().state
		},
		n => {
			debug!("State loaded from {} with size {}B, deserializing...", state_path, n);
			StfStateType::decode(&mut state_vec.as_slice())?
		},
	};
	trace!("state decoded successfully");
	// add empty state-diff
	let state_with_diff = StfState { state, state_diff: Default::default() };
	trace!("New state created: {:?}", state_with_diff);
	Ok(state_with_diff)
}

/// Writes the state (without the state diff) encrypted into the enclave storage
/// Returns the hash of the saved state (independent of the diff!)
fn write(state: StfState, shard: &ShardIdentifier) -> Result<H256> {
	let state_path =
		format!("{}/{}/{}", SHARDS_PATH, shard.encode().to_base58(), ENCRYPTED_STATE_FILE);
	trace!("writing state to: {}", state_path);

	// only save the state, the state diff is pruned
	let cyphertext = encrypt(state.state.encode())?;

	let state_hash = rsgx_sha256_slice(&cyphertext)?;

	debug!("new encrypted state with hash={:?} written to {}", state_hash, state_path);

	io_write(&cyphertext, &state_path)?;
	Ok(state_hash.into())
}

fn exists(shard: &ShardIdentifier) -> bool {
	Path::new(&format!("{}/{}/{}", SHARDS_PATH, shard.encode().to_base58(), ENCRYPTED_STATE_FILE))
		.exists()
}

fn init_shard(shard: &ShardIdentifier) -> Result<()> {
	let path = format!("{}/{}", SHARDS_PATH, shard.encode().to_base58());
	fs::create_dir_all(path.clone()).sgx_error()?;
	let mut file = fs::File::create(format!("{}/{}", path, ENCRYPTED_STATE_FILE)).sgx_error()?;
	Ok(file.write_all(b"")?)
}

fn read(path: &str) -> Result<Vec<u8>> {
	let mut bytes = io_read(path)?;

	if bytes.is_empty() {
		return Ok(bytes)
	}

	let state_hash = rsgx_sha256_slice(&bytes)?;
	debug!("read encrypted state with hash {:?} from {}", state_hash, path);

	AesSeal::unseal().map(|key| key.decrypt(&mut bytes))??;
	trace!("buffer decrypted = {:?}", bytes);

	Ok(bytes)
}

#[allow(unused)]
fn write_encrypted(bytes: &mut Vec<u8>, path: &str) -> Result<sgx_status_t> {
	debug!("plaintext data to be written: {:?}", bytes);
	AesSeal::unseal().map(|key| key.encrypt(bytes))?;
	io_write(&bytes, path)?;
	Ok(sgx_status_t::SGX_SUCCESS)
}

fn encrypt(mut state: Vec<u8>) -> Result<Vec<u8>> {
	AesSeal::unseal().map(|key| key.encrypt(&mut state))??;
	Ok(state)
}

fn list_shards() -> Result<Vec<ShardIdentifier>> {
	let files = match fs::read_dir(SHARDS_PATH).sgx_error() {
		Ok(f) => f,
		Err(_) => return Ok(Vec::new()),
	};
	let mut shards = Vec::new();
	for file in files {
		let s = file
			.sgx_error()?
			.file_name()
			.into_string()
			.sgx_error()?
			.from_base58()
			.sgx_error()?;
		shards.push(ShardIdentifier::decode(&mut s.as_slice()).sgx_error()?);
	}
	Ok(shards)
}

//  tests
#[cfg(feature = "test")]
pub mod tests {
	use super::*;
	use sgx_externalities::SgxExternalitiesTrait;
	use std::thread;

	// Fixme: Move this test to sgx-runtime:
	//
	// https://github.com/integritee-network/sgx-runtime/issues/23
	pub fn test_sgx_state_decode_encode_works() {
		// given
		let state = given_hello_world_state();

		// when
		let encoded_state = state.state.encode();
		let state2 = StfStateType::decode(&mut encoded_state.as_slice()).unwrap();

		// then
		assert_eq!(state.state, state2);
	}

	pub fn test_encrypt_decrypt_state_type_works() {
		// given
		let state = given_hello_world_state();

		// when
		let encrypted = encrypt(state.state.encode()).unwrap();

		let decrypted = encrypt(encrypted).unwrap();
		let decoded = StfStateType::decode(&mut decrypted.as_slice()).unwrap();

		// then
		assert_eq!(state.state, decoded);
	}

	pub fn test_write_and_load_state_works() {
		// given
		ensure_no_empty_shard_directory_exists();

		let state = given_hello_world_state();

		let shard: ShardIdentifier = [94u8; 32].into();
		given_initialized_shard(&shard);

		// when
		let _hash = write(state.clone(), &shard).unwrap();
		let result = load(&shard).unwrap();

		// then
		assert_eq!(state.state, result.state);

		// clean up
		remove_shard_dir(&shard);
	}

	pub fn test_write_access_locks_read_until_finished() {
		// here we want to test that a lock we obtain for
		// mutating state locks out any read attempt that happens during that time

		// given
		ensure_no_empty_shard_directory_exists();

		let shard: ShardIdentifier = [47u8; 32].into();
		given_initialized_shard(&shard);

		let state_handler = GlobalFileStateHandler;

		let new_state_key = "my_new_state".encode();
		let (lock, mut state_to_mutate) = state_handler.load_for_mutation(&shard).unwrap();

		// spawn a new thread that reads state
		// this thread should be blocked until the write lock is released, i.e. until
		// the new state is written. We can verify this, by trying to read that state variable
		// that will be inserted further down below
		let new_state_key_for_read = new_state_key.clone();
		let shard_for_read = shard.clone();
		let join_handle = thread::spawn(move || {
			let state_handler = GlobalFileStateHandler;
			let state_to_read = state_handler.load_initialized(&shard_for_read).unwrap();
			assert!(state_to_read.get(new_state_key_for_read.as_slice()).is_some());
		});

		assert!(state_to_mutate.get(new_state_key.clone().as_slice()).is_none());
		state_to_mutate.insert(new_state_key, "mega_secret_value".encode());

		let _hash = state_handler.write(state_to_mutate, lock, &shard).unwrap();

		join_handle.join().unwrap();

		// clean up
		remove_shard_dir(&shard);
	}

	fn ensure_no_empty_shard_directory_exists() {
		// ensure no empty states are within directory (created with init-shard)
		// otherwise an 'index out of bounds: the len is x but the index is x'
		// error will be thrown
		let shards = list_shards().unwrap();
		for shard in shards {
			if !exists(&shard) {
				init_shard(&shard).unwrap();
			}
		}
	}

	fn given_hello_world_state() -> StfState {
		let key: Vec<u8> = "hello".encode();
		let value: Vec<u8> = "world".encode();
		let mut state = StfState::new();
		state.insert(key, value);
		state
	}

	fn given_initialized_shard(shard: &ShardIdentifier) {
		if exists(&shard) {
			remove_shard_dir(shard);
		}
		init_shard(&shard).unwrap();
	}

	fn remove_shard_dir(shard: &ShardIdentifier) {
		std::fs::remove_dir_all(&format!("{}/{}", SHARDS_PATH, shard.encode().to_base58()))
			.unwrap();
	}
}
