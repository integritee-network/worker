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

//! Tests of tls-ra client / server communication.

use super::{
	mocks::SealHandlerMock, tls_ra_client::request_state_provisioning_internal,
	tls_ra_server::run_state_provisioning_server_internal,
};
use crate::{
	initialization::global_components::EnclaveStf,
	tls_ra::seal_handler::{SealHandler, SealStateAndKeys, UnsealStateAndKeys},
};
use ita_stf::State;
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider};
use itp_sgx_crypto::{mocks::KeyRepositoryMock, Aes};
use itp_stf_interface::InitState;
use itp_stf_primitives::types::AccountId;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::handle_state_mock::HandleStateMock;
use itp_types::ShardIdentifier;
use sgx_crypto_helper::{rsa3072::Rsa3072KeyPair, RsaKeyPair};
use sgx_types::sgx_quote_sign_type_t;
use std::{
	net::{TcpListener, TcpStream},
	os::unix::io::AsRawFd,
	string::String,
	sync::{Arc, SgxRwLock as RwLock},
	thread,
	time::Duration,
	vec::Vec,
};

static SIGN_TYPE: sgx_quote_sign_type_t = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
static SKIP_RA: i32 = 1;

fn run_state_provisioning_server(seal_handler: impl UnsealStateAndKeys, port: u16) {
	let listener = TcpListener::bind(server_addr(port)).unwrap();

	let (socket, _addr) = listener.accept().unwrap();
	run_state_provisioning_server_internal::<_, WorkerModeProvider>(
		socket.as_raw_fd(),
		SIGN_TYPE,
		SKIP_RA,
		seal_handler,
	)
	.unwrap();
}

fn server_addr(port: u16) -> String {
	format!("127.0.0.1:{}", port)
}

pub fn test_tls_ra_server_client_networking() {
	let shard = ShardIdentifier::default();
	let shielding_key_encoded = vec![1, 2, 3];
	let state_key_encoded = vec![5, 2, 3, 7];
	let state_encoded = Vec::from([1u8; 26000]); // Have a decently sized state, so read() must be called multiple times.

	let server_seal_handler = SealHandlerMock::new(
		Arc::new(RwLock::new(shielding_key_encoded.clone())),
		Arc::new(RwLock::new(state_key_encoded.clone())),
		Arc::new(RwLock::new(state_encoded.clone())),
	);
	let initial_client_state = vec![0, 0, 1];
	let initial_client_state_key = vec![0, 0, 2];
	let client_shielding_key = Arc::new(RwLock::new(Vec::new()));
	let client_state_key = Arc::new(RwLock::new(initial_client_state_key.clone()));
	let client_state = Arc::new(RwLock::new(initial_client_state.clone()));

	let client_seal_handler = SealHandlerMock::new(
		client_shielding_key.clone(),
		client_state_key.clone(),
		client_state.clone(),
	);

	let port: u16 = 3149;

	// Start server.
	let server_thread_handle = thread::spawn(move || {
		run_state_provisioning_server(server_seal_handler, port);
	});
	thread::sleep(Duration::from_secs(1));

	// Start client.
	let socket = TcpStream::connect(server_addr(port)).unwrap();
	let result = request_state_provisioning_internal(
		socket.as_raw_fd(),
		SIGN_TYPE,
		shard,
		SKIP_RA,
		client_seal_handler.clone(),
	);

	// Ensure server thread has finished.
	server_thread_handle.join().unwrap();

	assert!(result.is_ok());
	assert_eq!(*client_shielding_key.read().unwrap(), shielding_key_encoded);

	// State and state-key are provisioned only in sidechain mode
	if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
		assert_eq!(*client_state.read().unwrap(), state_encoded);
		assert_eq!(*client_state_key.read().unwrap(), state_key_encoded);
	} else {
		assert_eq!(*client_state.read().unwrap(), initial_client_state);
		assert_eq!(*client_state_key.read().unwrap(), initial_client_state_key);
	}
}

// Test state and key provisioning with 'real' data structures.
pub fn test_state_and_key_provisioning() {
	let state_key = Aes::new([3u8; 16], [0u8; 16]);
	let shielding_key = Rsa3072KeyPair::new().unwrap();
	let initialized_state = EnclaveStf::init_state(AccountId::new([1u8; 32]));
	let shard = ShardIdentifier::from([1u8; 32]);

	let server_seal_handler =
		create_seal_handler(state_key, shielding_key, initialized_state, &shard);
	let client_seal_handler =
		create_seal_handler(Aes::default(), Rsa3072KeyPair::default(), State::default(), &shard);

	let port: u16 = 3150;

	// Start server.
	let server_thread_handle = thread::spawn(move || {
		run_state_provisioning_server(server_seal_handler, port);
	});
	thread::sleep(Duration::from_secs(1));

	// Start client.
	let socket = TcpStream::connect(server_addr(port)).unwrap();
	let result = request_state_provisioning_internal(
		socket.as_raw_fd(),
		SIGN_TYPE,
		shard,
		SKIP_RA,
		client_seal_handler,
	);

	// Ensure server thread has finished.
	server_thread_handle.join().unwrap();

	assert!(result.is_ok());
}

fn create_seal_handler(
	state_key: Aes,
	shielding_key: Rsa3072KeyPair,
	state: State,
	shard: &ShardIdentifier,
) -> impl UnsealStateAndKeys + SealStateAndKeys {
	let state_key_repository = Arc::new(KeyRepositoryMock::<Aes>::new(state_key));
	let shielding_key_repository =
		Arc::new(KeyRepositoryMock::<Rsa3072KeyPair>::new(shielding_key));
	let state_handler = Arc::new(HandleStateMock::default());
	state_handler.reset(state, shard).unwrap();
	SealHandler::new(state_handler, state_key_repository, shielding_key_repository)
}
