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

//! Implementation of the client part of the state provisioning.

use super::{authentication::ServerAuth, Opcode, TcpHeader};
use crate::{
	attestation::create_ra_report_and_signature,
	error::{Error as EnclaveError, Result as EnclaveResult},
	initialization::global_components::{
		EnclaveSealHandler, GLOBAL_LIGHT_CLIENT_SEAL, GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_KEY_REPOSITORY_COMPONENT,
	},
	ocall::OcallApi,
	tls_ra::seal_handler::SealStateAndKeys,
	GLOBAL_STATE_HANDLER_COMPONENT,
};
use itp_attestation_handler::{RemoteAttestationType, DEV_HOSTNAME};
use itp_component_container::ComponentGetter;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_types::ShardIdentifier;
use log::*;
use rustls::{ClientConfig, ClientSession, Stream};
use sgx_types::*;
use std::{
	backtrace::{self, PrintFormat},
	io::{Read, Write},
	net::TcpStream,
	slice,
	sync::Arc,
	vec::Vec,
};

/// Client part of the TCP-level connection and the underlying TLS-level session.
///
/// Includes a seal handler, which handles the storage part of the received data.
struct TlsClient<'a, StateAndKeySealer>
where
	StateAndKeySealer: SealStateAndKeys,
{
	tls_stream: Stream<'a, ClientSession, TcpStream>,
	seal_handler: StateAndKeySealer,
	shard: ShardIdentifier,
}

impl<'a, StateAndKeySealer> TlsClient<'a, StateAndKeySealer>
where
	StateAndKeySealer: SealStateAndKeys,
{
	fn new(
		tls_stream: Stream<'a, ClientSession, TcpStream>,
		seal_handler: StateAndKeySealer,
		shard: ShardIdentifier,
	) -> TlsClient<StateAndKeySealer> {
		TlsClient { tls_stream, seal_handler, shard }
	}

	/// Read all data sent by the server of the specific shard.
	///
	/// We trust here that the server sends us the correct data, as
	/// we do not have any way to test it.
	fn read_shard(&mut self) -> EnclaveResult<()> {
		debug!("read_shard called, about to call self.write_shard().");
		self.write_shard()?;
		debug!("self.write_shard() succeeded.");
		self.read_and_seal_all()
	}

	/// Send the shard of the state we want to receive to the provisioning server.
	fn write_shard(&mut self) -> EnclaveResult<()> {
		debug!("self.write_shard() called.");
		self.tls_stream.write_all(self.shard.as_bytes())?;
		debug!("write_all succeeded.");
		Ok(())
	}

	/// Read and seal all relevant data sent by the server.
	fn read_and_seal_all(&mut self) -> EnclaveResult<()> {
		let mut received_payloads: Vec<Opcode> = Vec::new();

		loop {
			let maybe_opcode = self.read_and_seal()?;
			match maybe_opcode {
				None => break,
				Some(o) => {
					received_payloads.push(o);
				},
			}
		}
		info!("Successfully read and sealed all data sent by the state provisioning server.");

		// In case we receive a shielding key, but no state, we need to reset our state
		// to update the enclave account.
		if received_payloads.contains(&Opcode::ShieldingKey)
			&& !received_payloads.contains(&Opcode::State)
		{
			self.seal_handler.seal_new_empty_state(&self.shard)?;
		}

		Ok(())
	}

	/// Read a server header / payload pair and directly seal the received data.
	fn read_and_seal(&mut self) -> EnclaveResult<Option<Opcode>> {
		let mut start_byte = [0u8; 1];
		let read_size = self.tls_stream.read(&mut start_byte)?;
		// If we're reading but there's no data: EOF.
		if read_size == 0 {
			return Ok(None)
		}
		let header = self.read_header(start_byte[0])?;
		let bytes = self.read_until(header.payload_length as usize)?;
		match header.opcode {
			Opcode::ShieldingKey => self.seal_handler.seal_shielding_key(&bytes)?,
			Opcode::StateKey => self.seal_handler.seal_state_key(&bytes)?,
			Opcode::State => self.seal_handler.seal_state(&bytes, &self.shard)?,
			Opcode::LightClient => self.seal_handler.seal_light_client_state(&bytes)?,
		};
		Ok(Some(header.opcode))
	}

	/// Reads the payload header, indicating the sent payload length and type.
	fn read_header(&mut self, start_byte: u8) -> EnclaveResult<TcpHeader> {
		debug!("Read first byte: {:?}", start_byte);
		// The first sent byte indicates the payload type.
		let opcode: Opcode = start_byte.into();
		debug!("Read header opcode: {:?}", opcode);
		// The following bytes contain the payload length, which is a u64.
		let mut payload_length_buffer = [0u8; std::mem::size_of::<u64>()];
		self.tls_stream.read_exact(&mut payload_length_buffer)?;
		let payload_length = u64::from_be_bytes(payload_length_buffer);
		debug!("Payload length of {:?}: {}", opcode, payload_length);

		Ok(TcpHeader::new(opcode, payload_length))
	}

	/// Read all bytes into a buffer of given length.
	fn read_until(&mut self, length: usize) -> EnclaveResult<Vec<u8>> {
		let mut bytes = vec![0u8; length];
		self.tls_stream.read_exact(&mut bytes)?;
		Ok(bytes)
	}
}

#[no_mangle]
pub unsafe extern "C" fn request_state_provisioning(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	quoting_enclave_target_info: Option<&sgx_target_info_t>,
	quote_size: Option<&u32>,
	shard: *const u8,
	shard_size: u32,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));

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

	let light_client_seal = match GLOBAL_LIGHT_CLIENT_SEAL.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let seal_handler = EnclaveSealHandler::new(
		state_handler,
		state_key_repository,
		shielding_key_repository,
		light_client_seal,
	);

	if let Err(e) = request_state_provisioning_internal(
		socket_fd,
		sign_type,
		quoting_enclave_target_info,
		quote_size,
		shard,
		skip_ra,
		seal_handler,
	) {
		error!("Failed to sync state due to: {:?}", e);
		return e.into()
	};

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`request_state_provisioning`] function to be able to use the handy `?` operator.
pub(crate) fn request_state_provisioning_internal<StateAndKeySealer: SealStateAndKeys>(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	quoting_enclave_target_info: Option<&sgx_target_info_t>,
	quote_size: Option<&u32>,
	shard: ShardIdentifier,
	skip_ra: c_int,
	seal_handler: StateAndKeySealer,
) -> EnclaveResult<()> {
	debug!("Client config generate...");
	let client_config = tls_client_config(
		sign_type,
		quoting_enclave_target_info,
		quote_size,
		OcallApi,
		skip_ra == 1,
	)?;
	debug!("Client config retrieved");
	let (mut client_session, mut tcp_stream) = tls_client_session_stream(socket_fd, client_config)?;
	debug!("Client sesssion established.");

	let mut client = TlsClient::new(
		rustls::Stream::new(&mut client_session, &mut tcp_stream),
		seal_handler,
		shard,
	);

	info!("Requesting keys and state from mu-ra server of fellow validateer");
	client.read_shard()
}

fn tls_client_config<A: EnclaveAttestationOCallApi + 'static>(
	sign_type: sgx_quote_sign_type_t,
	quoting_enclave_target_info: Option<&sgx_target_info_t>,
	quote_size: Option<&u32>,
	ocall_api: A,
	skip_ra: bool,
) -> EnclaveResult<ClientConfig> {
	#[cfg(not(feature = "dcap"))]
	let attestation_type = RemoteAttestationType::Epid;
	#[cfg(feature = "dcap")]
	let attestation_type = RemoteAttestationType::Dcap;

	let (key_der, cert_der) = create_ra_report_and_signature(
		skip_ra,
		attestation_type,
		sign_type,
		quoting_enclave_target_info,
		quote_size,
	)?;
	debug!("got key_der and cert_der");

	let mut cfg = rustls::ClientConfig::new();
	let certs = vec![rustls::Certificate(cert_der)];
	let privkey = rustls::PrivateKey(key_der);

	cfg.set_single_client_cert(certs, privkey).unwrap();
	cfg.dangerous()
		.set_certificate_verifier(Arc::new(ServerAuth::new(true, skip_ra, ocall_api)));
	cfg.versions.clear();
	cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);
	Ok(cfg)
}

fn tls_client_session_stream(
	socket_fd: i32,
	client_config: ClientConfig,
) -> EnclaveResult<(ClientSession, TcpStream)> {
	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME)
		.map_err(|e| EnclaveError::Other(e.into()))?;
	let sess = rustls::ClientSession::new(&Arc::new(client_config), dns_name);
	let conn = TcpStream::new(socket_fd)?;
	Ok((sess, conn))
}
