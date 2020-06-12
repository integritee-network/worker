/*
    Copyright 2019 Supercomputing Systems AG

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

use std::fs;
use std::vec::Vec;
use std::io::Write;

use log::*;
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_types::*;

use crate::aes;
use crate::constants::{ENCRYPTED_STATE_FILE, SHARDS_PATH};
use crate::hex;
use crate::io;
use crate::utils::UnwrapOrSgxErrorUnexpected;
use base58::ToBase58;
use codec::Encode;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::H256;
use std::path::Path;
use substratee_stf::{ShardIdentifier, State as StfState, Stf};

pub fn load(shard: &ShardIdentifier) -> SgxResult<StfState> {
    // load last state
    let state_path = format!(
        "{}/{}/{}",
        SHARDS_PATH,
        shard.encode().to_base58(),
        ENCRYPTED_STATE_FILE
    );
    debug!("loading state from: {}", state_path);
    let state_vec = read(&state_path)?;

    // state is now decrypted!
    let state: StfState = match state_vec.len() {
        0 => {
            debug!("state is empty. will initialize it.");
            Stf::init_state()
        }
        n => {
            debug!("State loaded with size {}B, deserializing...", n);
            StfState::decode(state_vec)
        }
    };
    debug!("state decoded successfully");
    Ok(state)
}

pub fn write(state: StfState, shard: &ShardIdentifier) -> SgxResult<H256> {
    let state_path = format!(
        "{}/{}/{}",
        SHARDS_PATH,
        shard.encode().to_base58(),
        ENCRYPTED_STATE_FILE
    );
    debug!("writing state to: {}", state_path);

    let cyphertext = encrypt(state.encode())?;

    let state_hash = match rsgx_sha256_slice(&cyphertext) {
        Ok(h) => h,
        Err(status) => return Err(status),
    };

    debug!("new state hash=0x{}", hex::encode_hex(&state_hash));

    io::write(&cyphertext, &state_path)?;
    Ok(state_hash.into())
}

pub fn exists(shard: &ShardIdentifier) -> bool {
    Path::new(&format!(
        "{}/{}/{}",
        SHARDS_PATH,
        shard.encode().to_base58(),
        ENCRYPTED_STATE_FILE
    ))
    .exists()
}

pub fn init_shard(shard: &ShardIdentifier) -> SgxResult<()> {
    let path = format!("{}/{}", SHARDS_PATH, shard.encode().to_base58());
    fs::create_dir_all(path.clone()).sgx_error()?;
    let mut file = fs::File::create(format!("{}/{}", path, ENCRYPTED_STATE_FILE)).sgx_error()?;
    file.write_all(b"").sgx_error()
}

fn read(path: &str) -> SgxResult<Vec<u8>> {
    let mut bytes = match io::read(path) {
        Ok(vec) => match vec.len() {
            0 => return Ok(vec),
            _ => vec,
        },
        Err(e) => return Err(e),
    };

    aes::de_or_encrypt(&mut bytes)?;
    debug!("buffer decrypted = {:?}", bytes);

    Ok(bytes)
}

fn write_encrypted(bytes: &mut Vec<u8>, path: &str) -> SgxResult<sgx_status_t> {
    debug!("plaintext data to be written: {:?}", bytes);

    aes::de_or_encrypt(bytes)?;

    io::write(&bytes, path)?;
    Ok(sgx_status_t::SGX_SUCCESS)
}

fn encrypt(mut state: Vec<u8>) -> SgxResult<Vec<u8>> {
    aes::de_or_encrypt(&mut state)?;
    Ok(state)
}

pub fn test_encrypted_state_io_works() {
    let path = "test_state_file.bin";
    let plaintext = b"The quick brown fox jumps over the lazy dog.";
    aes::create_sealed().unwrap();

    aes::de_or_encrypt(&mut plaintext.to_vec()).unwrap();
    write_encrypted(&mut plaintext.to_vec(), path).unwrap();
    let state: Vec<u8> = read(path).unwrap();

    assert_eq!(state, plaintext.to_vec());
    std::fs::remove_file(path).unwrap();
}
