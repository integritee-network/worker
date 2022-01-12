use super::{Opcode, TcpHeader};
use crate::{
	attestation::{create_ra_report_and_signature, DEV_HOSTNAME},
	cert,
	error::{Error as EnclaveError, Result as EnclaveResult},
	ocall::OcallApi,
	tls_ra::key_handler::{KeyHandler, SealKeys},
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use log::*;
use rustls::{ClientConfig, ClientSession, Stream};
use sgx_types::*;
use std::{
	backtrace::{self, PrintFormat},
	io::Read,
	net::TcpStream,
	sync::Arc,
	vec::Vec,
};

/// Encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
struct TlsClient<'a, KeySealer>
where
	KeySealer: SealKeys,
{
	tls_stream: Stream<'a, ClientSession, TcpStream>,
	key_handler: KeySealer,
}

impl<'a, KeySealer> TlsClient<'a, KeySealer>
where
	KeySealer: SealKeys,
{
	fn new(
		tls_stream: Stream<'a, ClientSession, TcpStream>,
		key_handler: KeySealer,
	) -> TlsClient<KeySealer> {
		TlsClient { tls_stream, key_handler }
	}

	fn read_all(&mut self) -> EnclaveResult<()> {
		// We read two times in total for two keys.
		for _n in 0..2 {
			self.read()?;
		}
		Ok(())
	}

	fn read(&mut self) -> EnclaveResult<()> {
		let mut start_byte = [0u8; 1];
		let read_size = self.tls_stream.read(&mut start_byte)?;
		// If we're reading but there's no data: EOF.
		if read_size == 0 {
			return Err(EnclaveError::IO(std::io::Error::new(
				std::io::ErrorKind::UnexpectedEof,
				"EOF",
			)))
		}
		if let Some(header) = self.read_header(start_byte.to_vec()) {
			let bytes = self.read_until(header.payload_length as usize)?;
			match header.opcode {
				Opcode::ShieldingKey => self.key_handler.seal_shielding_key(&bytes)?,
				Opcode::SigningKey => self.key_handler.seal_signing_key(&bytes)?,
				_ => error!("received unexpected op: {:?}", header.opcode),
			}
		}

		Ok(())
	}

	fn read_header(&mut self, start_bytes: Vec<u8>) -> Option<TcpHeader> {
		let opcode: Opcode = start_bytes[0].into();
		let mut length_buffer = [0u8; 8];
		if let Err(rc) = self.tls_stream.read(&mut length_buffer) {
			error!("TLS read error: {:?}", rc);
			return None
		};
		let payload_length = u64::from_be_bytes(length_buffer);
		debug!("payload_length: {}", payload_length);

		Some(TcpHeader::new(opcode, payload_length))
	}

	fn read_until(&mut self, length: usize) -> EnclaveResult<Vec<u8>> {
		let mut bytes = vec![0u8; length];
		self.tls_stream.read(&mut bytes)?;
		Ok(bytes)
	}
}

#[no_mangle]
pub extern "C" fn request_state_provisioning(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let key_handler = KeyHandler {};

	if let Err(e) = request_state_provisioning_internal(socket_fd, sign_type, skip_ra, key_handler)
	{
		return e.into()
	};

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`request_state_provisioning`] function to be able to use the handy `?` operator.
pub(crate) fn request_state_provisioning_internal<KeySealer: SealKeys>(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
	key_handler: KeySealer,
) -> EnclaveResult<()> {
	let cfg = tls_client_config(sign_type, OcallApi, skip_ra == 1)?;

	let (mut client_session, mut tcp_stream) = tls_client_session_stream(socket_fd, cfg)?;

	let mut client =
		TlsClient::new(rustls::Stream::new(&mut client_session, &mut tcp_stream), key_handler);

	info!("Requesting keys and state from mu-ra server of fellow validateer");

	client.read_all()?;

	info!("    [Enclave] (MU-RA-Client) Registration procedure successful!");

	Ok(())
}

fn tls_client_config<A: EnclaveAttestationOCallApi + 'static>(
	sign_type: sgx_quote_sign_type_t,
	ocall_api: A,
	skip_ra: bool,
) -> EnclaveResult<ClientConfig> {
	let (key_der, cert_der) = create_ra_report_and_signature(sign_type, &ocall_api, skip_ra)?;

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
	cfg: ClientConfig,
) -> EnclaveResult<(ClientSession, TcpStream)> {
	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME)
		.map_err(|e| EnclaveError::Other(e.into()))?;
	let sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
	let conn = TcpStream::new(socket_fd)?;
	Ok((sess, conn))
}

struct ServerAuth<A> {
	outdated_ok: bool,
	skip_ra: bool,
	attestation_ocall: A,
}

impl<A> ServerAuth<A> {
	fn new(outdated_ok: bool, skip_ra: bool, attestation_ocall: A) -> Self {
		ServerAuth { outdated_ok, skip_ra, attestation_ocall }
	}
}

impl<A> rustls::ServerCertVerifier for ServerAuth<A>
where
	A: EnclaveAttestationOCallApi,
{
	fn verify_server_cert(
		&self,
		_roots: &rustls::RootCertStore,
		_certs: &[rustls::Certificate],
		_hostname: webpki::DNSNameRef,
		_ocsp: &[u8],
	) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		debug!("server cert: {:?}", _certs);

		if self.skip_ra {
			warn!("Skip verifying ra-report");
			return Ok(rustls::ServerCertVerified::assertion())
		}

		// This call will automatically verify cert is properly signed
		match cert::verify_mra_cert(&_certs[0].0, &self.attestation_ocall) {
			Ok(()) => Ok(rustls::ServerCertVerified::assertion()),
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) =>
				if self.outdated_ok {
					warn!("outdated_ok is set, overriding outdated error");
					Ok(rustls::ServerCertVerified::assertion())
				} else {
					Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
				},
			Err(_) => Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid)),
		}
	}
}
