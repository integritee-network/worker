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

//! Implementation of the server part of the state provisioning.

use super::{authentication::ClientAuth, Opcode, TcpHeader};
use crate::{
	attestation::create_ra_report_and_signature,
	error::{Error as EnclaveError, Result as EnclaveResult},
	global_components::{
		GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT, GLOBAL_STATE_KEY_REPOSITORY_COMPONENT,
	},
	ocall::OcallApi,
	tls_ra::seal_handler::{SealHandler, UnsealStateAndKeys},
	GLOBAL_STATE_HANDLER_COMPONENT,
};
use itp_component_container::ComponentGetter;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_types::ShardIdentifier;
use log::*;
use rustls::{ServerConfig, ServerSession, Stream};
use sgx_types::*;
use std::{
	backtrace::{self, PrintFormat},
	io::{Read, Write},
	net::TcpStream,
	sync::Arc,
};

/// Server part of the TCP-level connection and the underlying TLS-level session.
///
/// Includes a seal handler, which handles the reading part of the data to be sent.
struct TlsServer<'a, StateAndKeyUnsealer> {
	tls_stream: Stream<'a, ServerSession, TcpStream>,
	seal_handler: StateAndKeyUnsealer,
}

impl<'a, StateAndKeyUnsealer> TlsServer<'a, StateAndKeyUnsealer>
where
	StateAndKeyUnsealer: UnsealStateAndKeys,
{
	fn new(
		tls_stream: Stream<'a, ServerSession, TcpStream>,
		seal_handler: StateAndKeyUnsealer,
	) -> Self {
		Self { tls_stream, seal_handler }
	}

	/// Sends all relevant data of the specific shard to the client.
	fn write_shard(&mut self) -> EnclaveResult<()> {
		let shard = self.read_shard()?;
		self.write_all(&shard)
	}

	/// Read the shard of the state the client wants to receive.
	fn read_shard(&mut self) -> EnclaveResult<ShardIdentifier> {
		let mut shard_holder = ShardIdentifier::default();
		let shard = shard_holder.as_fixed_bytes_mut();
		self.tls_stream.read(shard)?;
		Ok(shard.into())
	}

	/// Sends all relevant data to the client.
	fn write_all(&mut self, shard: &ShardIdentifier) -> EnclaveResult<()> {
		let shielding_key = self.seal_handler.unseal_shielding_key()?;
		let state_key = self.seal_handler.unseal_state_key()?;
		let state = self.seal_handler.unseal_state(shard)?;
		self.write(Opcode::ShieldingKey, &shielding_key)?;
		self.write(Opcode::StateKey, &state_key)?;
		self.write(Opcode::State, &state)?;
		Ok(())
	}

	/// Sends the header followed by the payload.
	fn write(&mut self, opcode: Opcode, bytes: &[u8]) -> EnclaveResult<()> {
		self.write_header(TcpHeader::new(opcode, bytes.len() as u64))?;
		self.tls_stream.write(bytes)?;
		Ok(())
	}

	/// Sends the header which includes the payload length and the Opcode indicating the payload type.
	fn write_header(&mut self, tcp_header: TcpHeader) -> EnclaveResult<()> {
		self.tls_stream.write(&tcp_header.opcode.to_bytes())?;
		self.tls_stream.write(&tcp_header.payload_length.to_be_bytes())?;
		Ok(())
	}
}

#[no_mangle]
pub unsafe extern "C" fn run_state_provisioning_server(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let state_handler = match GLOBAL_STATE_HANDLER_COMPONENT.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let state_key_repository = match GLOBAL_STATE_KEY_REPOSITORY_COMPONENT.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let shielding_key_repository = match GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let seal_handler =
		SealHandler::new(state_handler, state_key_repository, shielding_key_repository);

	if let Err(e) =
		run_state_provisioning_server_internal(socket_fd, sign_type, skip_ra, seal_handler)
	{
		error!("Failed to provision state due to: {:?}", e);
		return e.into()
	};

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`run_state_provisioning_server`] function to be able to use the handy `?` operator.
pub(crate) fn run_state_provisioning_server_internal<StateAndKeyUnsealer: UnsealStateAndKeys>(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
	seal_handler: StateAndKeyUnsealer,
) -> EnclaveResult<()> {
	let server_config = tls_server_config(sign_type, OcallApi, skip_ra == 1)?;
	let (mut server_session, mut tcp_stream) = tls_server_session_stream(socket_fd, server_config)?;
	let mut server =
		TlsServer::new(rustls::Stream::new(&mut server_session, &mut tcp_stream), seal_handler);

	println!("    [Enclave] (MU-RA-Server) MU-RA successful sending keys");
	server.write_shard()
}

fn tls_server_session_stream(
	socket_fd: i32,
	server_config: ServerConfig,
) -> EnclaveResult<(ServerSession, TcpStream)> {
	let sess = rustls::ServerSession::new(&Arc::new(server_config));
	let conn = TcpStream::new(socket_fd).map_err(|e| EnclaveError::Other(e.into()))?;
	Ok((sess, conn))
}

fn tls_server_config<A: EnclaveAttestationOCallApi + 'static>(
	sign_type: sgx_quote_sign_type_t,
	ocall_api: A,
	skip_ra: bool,
) -> EnclaveResult<ServerConfig> {
	let (key_der, cert_der) = create_ra_report_and_signature(sign_type, &ocall_api, skip_ra)?;

	let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true, skip_ra, ocall_api)));
	let certs = vec![rustls::Certificate(cert_der)];
	let privkey = rustls::PrivateKey(key_der);
	cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
		.map_err(|e| EnclaveError::Other(e.into()))?;
	Ok(cfg)
}
