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
use itp_enclave_api::{
	error::Error,
	remote_attestation::{RemoteAttestation, TlsRemoteAttestation},
	EnclaveResult,
};
use itp_types::ShardIdentifier;
use log::*;
use sgx_types::*;
use std::{
	net::{TcpListener, TcpStream},
	os::unix::io::AsRawFd,
};

pub fn enclave_run_state_provisioning_server<E: TlsRemoteAttestation>(
	enclave_api: &E,
	sign_type: sgx_quote_sign_type_t,
	quoting_enclave_target_info: Option<&sgx_target_info_t>,
	quote_size: Option<&u32>,
	addr: &str,
	skip_ra: bool,
) {
	info!("Starting MU-RA-Server on: {}", addr);
	let listener = match TcpListener::bind(addr) {
		Ok(l) => l,
		Err(e) => {
			error!("error starting MU-RA server on {}: {}", addr, e);
			return
		},
	};
	loop {
		match listener.accept() {
			Ok((socket, addr)) => {
				info!("[MU-RA-Server] a worker at {} is requesting key provisiong", addr);

				let result = enclave_api.run_state_provisioning_server(
					socket.as_raw_fd(),
					sign_type,
					quoting_enclave_target_info,
					quote_size,
					skip_ra,
				);

				match result {
					Ok(_) => {
						debug!("[MU-RA-Server] ECALL success!");
					},
					Err(e) => {
						error!("[MU-RA-Server] ECALL Enclave Failed {:?}!", e);
					},
				}
			},
			Err(e) => error!("couldn't get client: {:?}", e),
		}
	}
}

pub fn enclave_request_state_provisioning<E: TlsRemoteAttestation + RemoteAttestation>(
	enclave_api: &E,
	sign_type: sgx_quote_sign_type_t,
	addr: &str,
	shard: &ShardIdentifier,
	skip_ra: bool,
) -> EnclaveResult<()> {
	info!("[MU-RA-Client] Requesting key provisioning from {}", addr);

	let stream = TcpStream::connect(addr).map_err(|e| Error::Other(Box::new(e)))?;

	let quoting_enclave_target_info = if !skip_ra {
		match enclave_api.qe_get_target_info() {
			Ok(quote_size) => Some(quote_size),
			Err(e) => return Err(e),
		}
	} else {
		None
	};

	let quote_size = if !skip_ra {
		match enclave_api.qe_get_quote_size() {
			Ok(quote_size) => Some(quote_size),
			Err(e) => return Err(e),
		}
	} else {
		None
	};

	enclave_api.request_state_provisioning(
		stream.as_raw_fd(),
		sign_type,
		quoting_enclave_target_info.as_ref(),
		quote_size.as_ref(),
		shard,
		skip_ra,
	)
}
