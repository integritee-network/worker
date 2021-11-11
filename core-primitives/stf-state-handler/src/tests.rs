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

use crate::{
	file_io::{encrypt, exists, init_shard, list_shards, load, write as state_write},
	global_file_state_handler::GlobalFileStateHandler,
	handle_state::HandleState,
};
use base58::ToBase58;
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType, Stf};
use itp_settings::files::SHARDS_PATH;
use itp_types::{ShardIdentifier, H256};
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::hashing::blake2_256;
use std::{format, thread, vec::Vec};

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
	let _hash = state_write(state.clone(), &shard).unwrap();
	let result = load(&shard).unwrap();

	// then
	assert_eq!(state.state, result.state);

	// clean up
	remove_shard_dir(&shard);
}

// Fixme: This test fails, see https://github.com/integritee-network/worker/issues/421
pub fn test_ensure_subsequent_state_loads_have_same_hash() {
	// given
	ensure_no_empty_shard_directory_exists();

	let shard: ShardIdentifier = [49u8; 32].into();
	given_initialized_shard(&shard);

	let state_handler = GlobalFileStateHandler;

	//state::write(state.clone(), &shard);
	let (lock, initial_state) = state_handler.load_for_mutation(&shard).unwrap();
	state_handler.write(initial_state.clone(), lock, &shard).unwrap();

	let state_loaded = state_handler.load_initialized(&shard).unwrap();

	// here we observe a different key order for the two states, which is why we get different hashes
	// for the state.
	//error!("State1: {:?}", initial_state.state);
	//error!("State2: {:?}", state_loaded.state);

	assert_eq!(hash_of(&initial_state.state), hash_of(&state_loaded.state));

	// clean up
	remove_shard_dir(&shard);
}

fn hash_of<T: Encode>(encodable: &T) -> H256 {
	encodable.using_encoded(blake2_256).into()
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
	std::fs::remove_dir_all(&format!("{}/{}", SHARDS_PATH, shard.encode().to_base58())).unwrap();
}
