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

use crate::error::{Error, Result};
use base58::{FromBase58, ToBase58};
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType, Stf};
use itp_settings::files::{ENCRYPTED_STATE_FILE, SHARDS_PATH};
use itp_sgx_crypto::{AesSeal, StateCrypto};
use itp_sgx_io::{read as io_read, write as io_write, SealedIO};
use itp_types::{ShardIdentifier, H256};
use log::*;
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::sgx_status_t;
use std::{format, fs, io::Write, path::Path, vec::Vec};

pub(crate) fn load_initialized_state(shard: &ShardIdentifier) -> Result<StfState> {
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

pub(crate) fn load(shard: &ShardIdentifier) -> Result<StfState> {
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
pub(crate) fn write(state: StfState, shard: &ShardIdentifier) -> Result<H256> {
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

pub(crate) fn exists(shard: &ShardIdentifier) -> bool {
	Path::new(&format!("{}/{}/{}", SHARDS_PATH, shard.encode().to_base58(), ENCRYPTED_STATE_FILE))
		.exists()
}

pub(crate) fn init_shard(shard: &ShardIdentifier) -> Result<()> {
	let path = format!("{}/{}", SHARDS_PATH, shard.encode().to_base58());
	fs::create_dir_all(path.clone())?;
	let mut file = fs::File::create(format!("{}/{}", path, ENCRYPTED_STATE_FILE))?;
	Ok(file.write_all(b"")?)
}

pub(crate) fn read(path: &str) -> Result<Vec<u8>> {
	let mut bytes = io_read(path)?;

	if bytes.is_empty() {
		return Ok(bytes)
	}

	let state_hash = rsgx_sha256_slice(&bytes)?;
	debug!(
		"read encrypted state with hash {:?} from {}",
		H256::from_slice(state_hash.as_ref()),
		path
	);

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

pub(crate) fn encrypt(mut state: Vec<u8>) -> Result<Vec<u8>> {
	AesSeal::unseal().map(|key| key.encrypt(&mut state))??;
	Ok(state)
}

pub(crate) fn list_shards() -> Result<Vec<ShardIdentifier>> {
	let files = match fs::read_dir(SHARDS_PATH) {
		Ok(f) => f,
		Err(_) => return Ok(Vec::new()),
	};
	let mut shards = Vec::new();
	for file_result in files {
		let s = file_result?
			.file_name()
			.into_string()
			.map_err(|_| Error::OsStringConversion)?
			.from_base58()?;

		shards.push(ShardIdentifier::decode(&mut s.as_slice())?);
	}
	Ok(shards)
}
