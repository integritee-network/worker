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
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider};
use itp_types::ShardIdentifier;
use sgx_types::sgx_quote_sign_type_t;
use std::{
	net::{TcpListener, TcpStream},
	os::unix::io::AsRawFd,
	sync::{Arc, SgxRwLock as RwLock},
	thread,
	time::Duration,
	vec::Vec,
};

static SERVER_ADDR: &str = "127.0.0.1:3149";
static SIGN_TYPE: sgx_quote_sign_type_t = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
static SKIP_RA: i32 = 1;

fn run_state_provisioning_server(seal_handler: SealHandlerMock) {
	let listener = TcpListener::bind(SERVER_ADDR).unwrap();

	let (socket, _addr) = listener.accept().unwrap();
	run_state_provisioning_server_internal::<_, WorkerModeProvider>(
		socket.as_raw_fd(),
		SIGN_TYPE,
		SKIP_RA,
		seal_handler.clone(),
	)
	.unwrap();
}

pub fn test_tls_ra_server_client_networking() {
	let shard = ShardIdentifier::default();
	let shielding_key = vec![1, 2, 3];
	let state_key = vec![5, 2, 3];
	let state = vec![5, 2, 3, 10, 21, 0, 9, 1];

	let server_seal_handler = SealHandlerMock::new(
		Arc::new(RwLock::new(shielding_key.clone())),
		Arc::new(RwLock::new(state_key.clone())),
		Arc::new(RwLock::new(state.clone())),
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

	// Start server.
	let server_thread_handle = thread::spawn(move || {
		run_state_provisioning_server(server_seal_handler);
	});
	thread::sleep(Duration::from_secs(1));

	// Start client.
	let socket = TcpStream::connect(SERVER_ADDR).unwrap();
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
	assert_eq!(*client_shielding_key.read().unwrap(), shielding_key);

	// State and state-key are provisioned only in sidechain mode
	if WorkerModeProvider::worker_mode() == WorkerMode::Sidechain {
		assert_eq!(*client_state.read().unwrap(), state);
		assert_eq!(*client_state_key.read().unwrap(), state_key);
	} else {
		assert_eq!(*client_state.read().unwrap(), initial_client_state);
		assert_eq!(*client_state_key.read().unwrap(), initial_client_state_key);
	}
}
