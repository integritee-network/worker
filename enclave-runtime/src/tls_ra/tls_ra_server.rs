use super::Opcode;
use crate::{
	attestation::create_ra_report_and_signature,
	cert,
	error::{Error as EnclaveError, Result as EnclaveResult},
	ocall::OcallApi,
};
use codec::Encode;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::{AesSeal, Rsa3072Seal};
use itp_sgx_io::SealedIO;
use log::*;
use rustls::{ServerConfig, ServerSession, Stream};
use sgx_types::*;
use std::{
	backtrace::{self, PrintFormat},
	io::Write,
	net::TcpStream,
	sync::Arc,
};
use webpki::DNSName;

fn send_signing_key(tls: &mut Stream<ServerSession, TcpStream>) -> EnclaveResult<()> {
	let aes = AesSeal::unseal()?;
	info!("    [Enclave] Read Signining Key: {:?}", aes);
	let aes_encoded = aes.encode();
	let payload_length: u64 = aes_encoded.len() as u64;
	tls.write(&Opcode::SigningKey.to_bytes())?;
	tls.write(&payload_length.to_be_bytes())?;
	tls.write(&aes_encoded)?;
	Ok(())
}

fn send_shielding_key(tls: &mut Stream<ServerSession, TcpStream>) -> EnclaveResult<()> {
	let shielding_key = Rsa3072Seal::unseal()?;
	info!("    [Enclave] Read Shielding Key: {:?}", shielding_key);
	let rsa_pair = serde_json::to_vec(&shielding_key).map_err(|e| EnclaveError::Other(e.into()))?;
	let payload_length: u64 = rsa_pair.len() as u64;
	tls.write(&Opcode::ShieldingKey.to_bytes())?;
	tls.write(&payload_length.to_be_bytes())?;
	tls.write(&rsa_pair)?;
	Ok(())
}

struct ClientAuth<A> {
	outdated_ok: bool,
	skip_ra: bool,
	attestation_ocall: A,
}

impl<A> ClientAuth<A> {
	fn new(outdated_ok: bool, skip_ra: bool, attestation_ocall: A) -> Self {
		ClientAuth { outdated_ok, skip_ra, attestation_ocall }
	}
}

impl<A> rustls::ClientCertVerifier for ClientAuth<A>
where
	A: EnclaveAttestationOCallApi,
{
	fn client_auth_root_subjects(
		&self,
		_sni: Option<&DNSName>,
	) -> Option<rustls::DistinguishedNames> {
		Some(rustls::DistinguishedNames::new())
	}

	fn verify_client_cert(
		&self,
		_certs: &[rustls::Certificate],
		_sni: Option<&DNSName>,
	) -> Result<rustls::ClientCertVerified, rustls::TLSError> {
		debug!("client cert: {:?}", _certs);
		// This call will automatically verify cert is properly signed
		if self.skip_ra {
			warn!("Skip verifying ra-report");
			return Ok(rustls::ClientCertVerified::assertion())
		}

		match cert::verify_mra_cert(&_certs[0].0, &self.attestation_ocall) {
			Ok(()) => Ok(rustls::ClientCertVerified::assertion()),
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) =>
				if self.outdated_ok {
					warn!("outdated_ok is set, overriding outdated error");
					Ok(rustls::ClientCertVerified::assertion())
				} else {
					Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
				},
			Err(_) => Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid)),
		}
	}
}

#[no_mangle]
pub unsafe extern "C" fn run_key_provisioning_server(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	if let Err(e) = run_key_provisioning_server_internal(socket_fd, sign_type, skip_ra) {
		return e.into()
	};

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`run_key_provisioning_server`] function to be able to use the handy `?` operator.
fn run_key_provisioning_server_internal(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> EnclaveResult<()> {
	let cfg = tls_server_config(sign_type, OcallApi, skip_ra == 1)?;
	let (mut server_session, mut tcp_stream) = tls_server_session_stream(socket_fd, cfg)?;

	let mut tls = rustls::Stream::new(&mut server_session, &mut tcp_stream);
	println!("    [Enclave] (MU-RA-Server) MU-RA successful sending keys");

	send_shielding_key(&mut tls)?;
	send_signing_key(&mut tls)?;

	Ok(())
}

fn tls_server_session_stream(
	socket_fd: i32,
	cfg: ServerConfig,
) -> EnclaveResult<(ServerSession, TcpStream)> {
	let sess = rustls::ServerSession::new(&Arc::new(cfg));
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
