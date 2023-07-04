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
	file_io::{sgx::SgxStateFileIo, StateDir, StateFileIo},
	handle_state::HandleState,
	in_memory_state_file_io::sgx::create_in_memory_state_io_from_shards_directories,
	query_shard_state::QueryShardState,
	state_handler::StateHandler,
	state_snapshot_repository::{StateSnapshotRepository, VersionedStateAccess},
	state_snapshot_repository_loader::StateSnapshotRepositoryLoader,
	test::mocks::initialize_state_mock::InitializeStateMock,
};
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType};
use itp_hashing::Hash;
use itp_sgx_crypto::{
	get_aes_repository,
	key_repository::{AccessKey, KeyRepository},
	Aes, AesSeal, StateCrypto,
};
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
use itp_sgx_io::write;
use itp_sgx_temp_dir::TempDir;
use itp_stf_state_observer::state_observer::StateObserver;
use itp_types::{ShardIdentifier, H256};
use std::{sync::Arc, thread, vec::Vec};

const STATE_SNAPSHOTS_CACHE_SIZE: usize = 3;

type StateKeyRepository = KeyRepository<Aes, AesSeal>;
type TestStateInitializer = InitializeStateMock<StfState>;
type TestStateFileIo = SgxStateFileIo<StateKeyRepository, SgxExternalities>;
type TestStateRepository = StateSnapshotRepository<TestStateFileIo>;
type TestStateRepositoryLoader =
	StateSnapshotRepositoryLoader<TestStateFileIo, TestStateInitializer>;
type TestStateObserver = StateObserver<StfState>;
type TestStateHandler = StateHandler<TestStateRepository, TestStateObserver, TestStateInitializer>;

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
	let temp_dir = TempDir::with_prefix("test_encrypt_decrypt_state_type_works").unwrap();
	let state_key = get_aes_repository(temp_dir.path().to_path_buf())
		.unwrap()
		.retrieve_key()
		.unwrap();

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
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_write_and_load_state_works", &shard);

	let state_handler = initialize_state_handler(state_key_access, state_dir);

	let state = given_hello_world_state();

	// when
	let (lock, _s) = state_handler.load_for_mutation(&shard).unwrap();
	let _hash = state_handler.write_after_mutation(state.clone(), lock, &shard).unwrap();

	let (result_state, _) = state_handler.load_cloned(&shard).unwrap();

	// then
	assert_eq!(state.state, result_state.state);
}

pub fn test_ensure_subsequent_state_loads_have_same_hash() {
	// given
	let shard: ShardIdentifier = [49u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_ensure_subsequent_state_loads_have_same_hash", &shard);

	let state_handler = initialize_state_handler(state_key_access, state_dir);

	let (lock, initial_state) = state_handler.load_for_mutation(&shard).unwrap();
	state_handler.write_after_mutation(initial_state.clone(), lock, &shard).unwrap();

	let (_, loaded_state_hash) = state_handler.load_cloned(&shard).unwrap();

	assert_eq!(initial_state.hash(), loaded_state_hash);
}

pub fn test_write_access_locks_read_until_finished() {
	// here we want to test that a lock we obtain for
	// mutating state locks out any read attempt that happens during that time

	// given
	let shard: ShardIdentifier = [47u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_write_access_locks_read_until_finished", &shard);

	let state_handler = initialize_state_handler(state_key_access, state_dir);

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
		let (state_to_read, _) = state_handler_clone.load_cloned(&shard_for_read).unwrap();
		assert!(state_to_read.get(new_state_key_for_read.as_slice()).is_some());
	});

	assert!(state_to_mutate.get(new_state_key.clone().as_slice()).is_none());
	state_to_mutate.insert(new_state_key, "mega_secret_value".encode());

	let _hash = state_handler.write_after_mutation(state_to_mutate, lock, &shard).unwrap();

	join_handle.join().unwrap();
}

pub fn test_state_handler_file_backend_is_initialized() {
	let shard: ShardIdentifier = [11u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_state_handler_file_backend_is_initialized", &shard);

	let state_handler = initialize_state_handler(state_key_access, state_dir.clone());

	assert!(state_handler.shard_exists(&shard).unwrap());
	assert!(1 <= state_handler.list_shards().unwrap().len()); // only greater equal, because there might be other (non-test) shards present
	assert_eq!(1, state_dir.list_state_ids_for_shard(&shard).unwrap().len()); // creates a first initialized file

	let _state = state_handler.load_cloned(&shard).unwrap();

	assert_eq!(1, state_dir.list_state_ids_for_shard(&shard).unwrap().len());
}

pub fn test_multiple_state_updates_create_snapshots_up_to_cache_size() {
	let shard: ShardIdentifier = [17u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_state_handler_file_backend_is_initialized", &shard);

	let state_handler = initialize_state_handler(state_key_access, state_dir.clone());

	assert_eq!(1, state_dir.list_state_ids_for_shard(&shard).unwrap().len());

	let hash_1 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_1".encode(), "mega_secret_value".encode()),
	);
	assert_eq!(2, state_dir.list_state_ids_for_shard(&shard).unwrap().len());

	let hash_2 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_2".encode(), "mega_secret_value222".encode()),
	);
	assert_eq!(3, state_dir.list_state_ids_for_shard(&shard).unwrap().len());

	let hash_3 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_3".encode(), "mega_secret_value3".encode()),
	);
	assert_eq!(3, state_dir.list_state_ids_for_shard(&shard).unwrap().len());

	let hash_4 = update_state(
		state_handler.as_ref(),
		&shard,
		("my_key_3".encode(), "mega_secret_valuenot3".encode()),
	);
	assert_eq!(3, state_dir.list_state_ids_for_shard(&shard).unwrap().len());

	assert_ne!(hash_1, hash_2);
	assert_ne!(hash_1, hash_3);
	assert_ne!(hash_1, hash_4);
	assert_ne!(hash_2, hash_3);
	assert_ne!(hash_2, hash_4);
	assert_ne!(hash_3, hash_4);

	assert_eq!(
		STATE_SNAPSHOTS_CACHE_SIZE,
		state_dir.list_state_ids_for_shard(&shard).unwrap().len()
	);
}

pub fn test_file_io_get_state_hash_works() {
	let shard: ShardIdentifier = [21u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_file_io_get_state_hash_works", &shard);

	let file_io = TestStateFileIo::new(state_key_access, state_dir);

	let state_id = 1234u128;
	let state_hash = file_io
		.initialize_shard(&shard, state_id, &StfState::new(Default::default()))
		.unwrap();
	assert_eq!(state_hash, file_io.compute_hash(&shard, state_id).unwrap());

	let state_hash = file_io.write(&shard, state_id, &given_hello_world_state()).unwrap();
	assert_eq!(state_hash, file_io.compute_hash(&shard, state_id).unwrap());
}

pub fn test_state_files_from_handler_can_be_loaded_again() {
	let shard: ShardIdentifier = [15u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_state_files_from_handler_can_be_loaded_again", &shard);

	let state_handler = initialize_state_handler(state_key_access.clone(), state_dir.clone());

	update_state(state_handler.as_ref(), &shard, ("test_key_1".encode(), "value1".encode()));
	update_state(state_handler.as_ref(), &shard, ("test_key_2".encode(), "value2".encode()));
	update_state(
		state_handler.as_ref(),
		&shard,
		("test_key_2".encode(), "value2_updated".encode()),
	);
	update_state(state_handler.as_ref(), &shard, ("test_key_3".encode(), "value3".encode()));

	// We initialize another state handler to load the state from the changes we just made.
	let updated_state_handler = initialize_state_handler(state_key_access, state_dir.clone());

	assert_eq!(
		STATE_SNAPSHOTS_CACHE_SIZE,
		state_dir.list_state_ids_for_shard(&shard).unwrap().len()
	);
	assert_eq!(
		&"value3".encode(),
		updated_state_handler
			.load_cloned(&shard)
			.unwrap()
			.0
			.state()
			.get("test_key_3".encode().as_slice())
			.unwrap()
	);
}

pub fn test_list_state_ids_ignores_files_not_matching_the_pattern() {
	let shard: ShardIdentifier = [21u8; 32].into();
	let (_temp_dir, state_key_access, state_dir) =
		test_setup("test_list_state_ids_ignores_files_not_matching_the_pattern", &shard);

	let file_io = TestStateFileIo::new(state_key_access, state_dir.clone());

	let invalid_state_file_path = state_dir.shard_path(&shard).join("invalid-state.bin");
	write(&[0, 1, 2, 3, 4, 5], invalid_state_file_path).unwrap();

	file_io
		.initialize_shard(&shard, 1234, &StfState::new(Default::default()))
		.unwrap();

	assert_eq!(1, file_io.list_state_ids_for_shard(&shard).unwrap().len());
}

pub fn test_in_memory_state_initializes_from_shard_directory() {
	let shard: ShardIdentifier = [45u8; 32].into();
	let (_temp_dir, _, state_dir) =
		test_setup("test_list_state_ids_ignores_files_not_matching_the_pattern", &shard);

	let file_io =
		create_in_memory_state_io_from_shards_directories(&state_dir.shards_directory()).unwrap();
	let state_initializer = Arc::new(TestStateInitializer::new(StfState::new(Default::default())));
	let state_repository_loader =
		StateSnapshotRepositoryLoader::new(file_io.clone(), state_initializer);
	let state_snapshot_repository = state_repository_loader
		.load_snapshot_repository(STATE_SNAPSHOTS_CACHE_SIZE)
		.unwrap();

	assert_eq!(1, file_io.get_states_for_shard(&shard).unwrap().len());
	assert!(state_snapshot_repository.shard_exists(&shard));
}

fn initialize_state_handler(
	state_key_access: Arc<StateKeyRepository>,
	state_dir: StateDir,
) -> Arc<TestStateHandler> {
	let file_io = Arc::new(TestStateFileIo::new(state_key_access, state_dir));
	let state_initializer = Arc::new(TestStateInitializer::new(StfState::new(Default::default())));
	let state_repository_loader =
		TestStateRepositoryLoader::new(file_io, state_initializer.clone());
	let state_observer = Arc::new(TestStateObserver::default());
	let state_snapshot_repository = state_repository_loader
		.load_snapshot_repository(STATE_SNAPSHOTS_CACHE_SIZE)
		.unwrap();
	Arc::new(
		TestStateHandler::load_from_repository(
			state_snapshot_repository,
			state_observer,
			state_initializer,
		)
		.unwrap(),
	)
}

fn update_state(
	state_handler: &TestStateHandler,
	shard: &ShardIdentifier,
	kv_pair: (Vec<u8>, Vec<u8>),
) -> H256 {
	let (lock, mut state_to_mutate) = state_handler.load_for_mutation(shard).unwrap();
	state_to_mutate.insert(kv_pair.0, kv_pair.1);
	state_handler.write_after_mutation(state_to_mutate, lock, shard).unwrap()
}

fn given_hello_world_state() -> StfState {
	let key: Vec<u8> = "hello".encode();
	let value: Vec<u8> = "world".encode();
	let mut state = StfState::new(Default::default());
	state.insert(key, value);
	state
}

fn test_setup(id: &str, shard: &ShardIdentifier) -> (TempDir, Arc<StateKeyRepository>, StateDir) {
	let temp_dir = TempDir::with_prefix(id).unwrap();
	let state_key_access = Arc::new(get_aes_repository(temp_dir.path().to_path_buf()).unwrap());
	let state_dir = StateDir::new(temp_dir.path().to_path_buf());
	state_dir.given_initialized_shard(shard);

	(temp_dir, state_key_access, state_dir)
}
