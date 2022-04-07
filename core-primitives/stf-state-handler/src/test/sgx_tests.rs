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
	file_io::{
		init_shard, remove_shard_dir, sgx::SgxStateFileIo, shard_exists, shard_path, StateFileIo,
	},
	handle_state::HandleState,
	query_shard_state::QueryShardState,
	state_handler::StateHandler,
	state_snapshot_repository::StateSnapshotRepository,
	state_snapshot_repository_loader::StateSnapshotRepositoryLoader,
};
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType};
use itp_sgx_crypto::{Aes, AesSeal, StateCrypto};
use itp_sgx_io::SealedIO;
use itp_types::{ShardIdentifier, H256};
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::hashing::blake2_256;
use std::{sync::Arc, thread, vec::Vec};

const STATE_SNAPSHOTS_CACHE_SIZE: usize = 3;

type TestStateFileIo = SgxStateFileIo<Aes>;
type TestStateRepository = StateSnapshotRepository<TestStateFileIo, StfState, H256>;
type TestStateRepositoryLoader = StateSnapshotRepositoryLoader<TestStateFileIo, StfState, H256>;
type TestStateHandler = StateHandler<TestStateRepository>;

/// Directory handle to automatically initialize a directory
/// and upon dropping the reference, removing it again.
struct ShardDirectoryHandle {
	shard: ShardIdentifier,
}

impl ShardDirectoryHandle {
	pub fn new(shard: ShardIdentifier) -> Result<Self> {
		given_initialized_shard(&shard)?;
		Ok(ShardDirectoryHandle { shard })
	}
}

impl Drop for ShardDirectoryHandle {
	fn drop(&mut self) {
		remove_shard_dir(&self.shard)
	}
}

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
	let state_key = AesSeal::unseal().unwrap();

	// when
	let mut state_buffer = state.state.encode();
	state_key.encrypt(&mut state_buffer).unwrap();

	state_key.decrypt(&mut state_buffer).unwrap();
	let decoded = StfStateType::decode(&mut state_buffer.as_slice()).unwrap();

	// then
	assert_eq!(state.state, decoded);
}

pub fn test_write_and_load_state_works() {
	// given
	let shard: ShardIdentifier = [94u8; 32].into();
	let (state_handler, shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	let state = given_hello_world_state();

	// when
	let (lock, _s) = state_handler.load_for_mutation(&shard).unwrap();
	let _hash = state_handler.write(state.clone(), lock, &shard).unwrap();

	let result = state_handler.load(&shard).unwrap();

	// then
	assert_eq!(state.state, result.state);

	// clean up
	std::mem::drop(shard_dir_handle);
}

pub fn test_ensure_subsequent_state_loads_have_same_hash() {
	// given
	let shard: ShardIdentifier = [49u8; 32].into();
	let (state_handler, shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	let (lock, initial_state) = state_handler.load_for_mutation(&shard).unwrap();
	state_handler.write(initial_state.clone(), lock, &shard).unwrap();

	let state_loaded = state_handler.load(&shard).unwrap();

	assert_eq!(hash_of(&initial_state.state), hash_of(&state_loaded.state));

	// clean up
	std::mem::drop(shard_dir_handle);
}

fn hash_of<T: Encode>(encodable: &T) -> H256 {
	encodable.using_encoded(blake2_256).into()
}

pub fn test_write_access_locks_read_until_finished() {
	// here we want to test that a lock we obtain for
	// mutating state locks out any read attempt that happens during that time

	// given
	let shard: ShardIdentifier = [47u8; 32].into();
	let (state_handler, shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	let new_state_key = "my_new_state".encode();
	let (lock, mut state_to_mutate) = state_handler.load_for_mutation(&shard).unwrap();

	// spawn a new thread that reads state
	// this thread should be blocked until the write lock is released, i.e. until
	// the new state is written. We can verify this, by trying to read that state variable
	// that will be inserted further down below
	let new_state_key_for_read = new_state_key.clone();
	let state_handler_clone = state_handler.clone();
	let shard_for_read = shard.clone();
	let join_handle = thread::spawn(move || {
		let state_to_read = state_handler_clone.load(&shard_for_read).unwrap();
		assert!(state_to_read.get(new_state_key_for_read.as_slice()).is_some());
	});

	assert!(state_to_mutate.get(new_state_key.clone().as_slice()).is_none());
	state_to_mutate.insert(new_state_key, "mega_secret_value".encode());

	let _hash = state_handler.write(state_to_mutate, lock, &shard).unwrap();

	join_handle.join().unwrap();

	// clean up
	std::mem::drop(shard_dir_handle);
}

pub fn test_state_handler_file_backend_is_initialized() {
	let shard: ShardIdentifier = [11u8; 32].into();
	let (state_handler, shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	assert!(state_handler.shard_exists(&shard).unwrap());
	assert!(1 <= state_handler.list_shards().unwrap().len()); // only greater equal, because there might be other (non-test) shards present
	assert_eq!(1, number_of_files_in_shard_dir(&shard).unwrap()); // creates a first initialized file

	let _state = state_handler.load(&shard).unwrap();

	assert_eq!(1, number_of_files_in_shard_dir(&shard).unwrap());

	// clean up
	std::mem::drop(shard_dir_handle);
}

pub fn test_multiple_state_updates_create_snapshots_up_to_cache_size() {
	let shard: ShardIdentifier = [17u8; 32].into();
	let (state_handler, _shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	assert_eq!(1, number_of_files_in_shard_dir(&shard).unwrap());

	let hash_1 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_1".encode(), "mega_secret_value".encode()),
	);
	assert_eq!(2, number_of_files_in_shard_dir(&shard).unwrap());

	let hash_2 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_2".encode(), "mega_secret_value222".encode()),
	);
	assert_eq!(3, number_of_files_in_shard_dir(&shard).unwrap());

	let hash_3 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_3".encode(), "mega_secret_value3".encode()),
	);
	assert_eq!(3, number_of_files_in_shard_dir(&shard).unwrap());

	let hash_4 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_3".encode(), "mega_secret_valuenot3".encode()),
	);
	assert_eq!(3, number_of_files_in_shard_dir(&shard).unwrap());

	assert_ne!(hash_1, hash_2);
	assert_ne!(hash_1, hash_3);
	assert_ne!(hash_1, hash_4);
	assert_ne!(hash_2, hash_3);
	assert_ne!(hash_2, hash_4);
	assert_ne!(hash_3, hash_4);

	assert_eq!(STATE_SNAPSHOTS_CACHE_SIZE, number_of_files_in_shard_dir(&shard).unwrap());
}

pub fn test_file_io_get_state_hash_works() {
	let shard: ShardIdentifier = [21u8; 32].into();
	let _shard_dir_handle = ShardDirectoryHandle::new(shard).unwrap();

	let file_io = TestStateFileIo::new(AesSeal::unseal().unwrap());

	let file_name = "1234_state.bin";
	let state_hash = file_io.create_initialized(&shard, file_name).unwrap();
	assert_eq!(state_hash, file_io.compute_hash(&shard, file_name).unwrap());

	let state_hash = file_io.write(&shard, file_name, given_hello_world_state()).unwrap();
	assert_eq!(state_hash, file_io.compute_hash(&shard, file_name).unwrap());
}

pub fn test_state_files_from_handler_can_be_loaded_again() {
	let shard: ShardIdentifier = [15u8; 32].into();
	let (state_handler, _shard_dir_handle) = initialize_state_handler_with_directory_handle(&shard);

	update_state(state_handler.as_ref(), &shard, ("test_key_1".encode(), "value1".encode()));
	update_state(state_handler.as_ref(), &shard, ("test_key_2".encode(), "value2".encode()));
	update_state(
		state_handler.as_ref(),
		&shard,
		("test_key_2".encode(), "value2_updated".encode()),
	);
	update_state(state_handler.as_ref(), &shard, ("test_key_3".encode(), "value3".encode()));

	// We initialize another state handler to load the state from the changes we just made.
	let updated_state_handler = initialize_state_handler();

	assert_eq!(STATE_SNAPSHOTS_CACHE_SIZE, number_of_files_in_shard_dir(&shard).unwrap());
	assert_eq!(
		&"value3".encode(),
		updated_state_handler
			.load(&shard)
			.unwrap()
			.state()
			.get("test_key_3".encode().as_slice())
			.unwrap()
	);
}

fn initialize_state_handler_with_directory_handle(
	shard: &ShardIdentifier,
) -> (Arc<TestStateHandler>, ShardDirectoryHandle) {
	let shard_dir_handle = ShardDirectoryHandle::new(*shard).unwrap();
	(initialize_state_handler(), shard_dir_handle)
}

fn initialize_state_handler() -> Arc<TestStateHandler> {
	let state_key = AesSeal::unseal().unwrap();
	let file_io = Arc::new(TestStateFileIo::new(state_key));
	let state_repository_loader = TestStateRepositoryLoader::new(file_io);
	let state_snapshot_repository =
		state_repository_loader.load_from_files(STATE_SNAPSHOTS_CACHE_SIZE).unwrap();
	Arc::new(TestStateHandler::new(state_snapshot_repository))
}

fn update_state(
	state_handler: &TestStateHandler,
	shard: &ShardIdentifier,
	kv_pair: (Vec<u8>, Vec<u8>),
) -> H256 {
	let (lock, mut state_to_mutate) = state_handler.load_for_mutation(shard).unwrap();
	state_to_mutate.insert(kv_pair.0, kv_pair.1);
	state_handler.write(state_to_mutate, lock, shard).unwrap()
}

fn given_hello_world_state() -> StfState {
	let key: Vec<u8> = "hello".encode();
	let value: Vec<u8> = "world".encode();
	let mut state = StfState::new();
	state.insert(key, value);
	state
}

fn given_initialized_shard(shard: &ShardIdentifier) -> Result<()> {
	if shard_exists(&shard) {
		remove_shard_dir(shard);
	}
	init_shard(&shard)
}

fn number_of_files_in_shard_dir(shard: &ShardIdentifier) -> Result<usize> {
	let shard_dir_path = shard_path(shard);
	let files_in_dir = std::fs::read_dir(shard_dir_path).map_err(|e| Error::Other(e.into()))?;
	Ok(files_in_dir.count())
}
