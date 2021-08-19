use crate::{
	aes::Aes,
	attestation::{create_ra_report_and_signature, DEV_HOSTNAME},
	cert,
	error::Result as EnclaveResult,
	ocall::ocall_component_factory::{OCallComponentFactory, OCallComponentFactoryTrait},
	rsa3072,
	utils::UnwrapOrSgxErrorUnexpected,
};
use log::*;
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Stream};
use sgx_types::*;
use std::{
	backtrace::{self, PrintFormat},
	io::{Read, Write},
	net::TcpStream,
	sync::Arc,
	vec::Vec,
};
use substratee_ocall_api::EnclaveAttestationOCallApi;
use substratee_sgx_io::SealedIO;
use webpki::DNSName;

struct ClientAuth<A> {
	outdated_ok: bool,
	skip_ra: bool,
	attestation_ocall: Arc<A>,
}

impl<A> ClientAuth<A> {
	fn new(outdated_ok: bool, skip_ra: bool, attestation_ocall: Arc<A>) -> Self {
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

		match cert::verify_mra_cert(&_certs[0].0, self.attestation_ocall.as_ref()) {
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

struct ServerAuth<A> {
	outdated_ok: bool,
	skip_ra: bool,
	attestation_ocall: Arc<A>,
}

impl<A> ServerAuth<A> {
	fn new(outdated_ok: bool, skip_ra: bool, attestation_ocall: Arc<A>) -> Self {
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
		match cert::verify_mra_cert(&_certs[0].0, self.attestation_ocall.as_ref()) {
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

#[no_mangle]
pub unsafe extern "C" fn run_key_provisioning_server(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let ocall_api = OCallComponentFactory::attestation_api();

	let cfg = match tls_server_config(sign_type, ocall_api, skip_ra == 1) {
		Ok(cfg) => cfg,
		Err(e) => return e,
	};

	let (mut sess, mut conn) = match tls_server_sesssion_stream(socket_fd, cfg) {
		Ok(sc) => sc,
		Err(e) => return e,
	};

	let mut tls = rustls::Stream::new(&mut sess, &mut conn);
	println!("    [Enclave] (MU-RA-Server) MU-RA successful sending keys");

	let (rsa_pair, aes) = match read_files_to_send() {
		Ok((r, a)) => (r, a),
		Err(e) => return e,
	};

	match send_files(&mut tls, &rsa_pair, &aes) {
		Ok(_) => println!("    [Enclave] (MU-RA-Server) Successfully provisioned keys!\n"),
		Err(e) => return e,
	}

	sgx_status_t::SGX_SUCCESS
}

fn tls_server_sesssion_stream(
	socket_fd: i32,
	cfg: ServerConfig,
) -> SgxResult<(ServerSession, TcpStream)> {
	let sess = rustls::ServerSession::new(&Arc::new(cfg));
	let conn = TcpStream::new(socket_fd).sgx_error()?;
	Ok((sess, conn))
}

fn tls_server_config<A: EnclaveAttestationOCallApi + 'static>(
	sign_type: sgx_quote_sign_type_t,
	ocall_api: Arc<A>,
	skip_ra: bool,
) -> SgxResult<ServerConfig> {
	let (key_der, cert_der) =
		create_ra_report_and_signature(sign_type, ocall_api.clone(), skip_ra).sgx_error()?;

	let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true, skip_ra, ocall_api)));
	let certs = vec![rustls::Certificate(cert_der)];
	let privkey = rustls::PrivateKey(key_der);
	cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
		.sgx_error()?;
	Ok(cfg)
}

fn read_files_to_send() -> SgxResult<(Vec<u8>, Aes)> {
	let shielding_key = rsa3072::unseal_pair().sgx_error()?;
	let aes = Aes::unseal().sgx_error()?;
	let rsa_pair = serde_json::to_string(&shielding_key).sgx_error()?;

	let rsa_len = rsa_pair.as_bytes().len();
	info!("    [Enclave] Read Shielding Key: {:?}", rsa_len);
	info!("    [Enclave] Read AES key {:?}", aes);

	Ok((rsa_pair.as_bytes().to_vec(), aes))
}

fn send_files(
	tls: &mut Stream<ServerSession, TcpStream>,
	rsa_pair: &[u8],
	aes: &Aes,
) -> SgxResult<()> {
	tls.write(&rsa_pair.len().to_le_bytes()).sgx_error()?;
	tls.write(&rsa_pair).sgx_error()?;
	tls.write(&aes.key[..]).sgx_error()?;
	tls.write(&aes.init_vec[..]).sgx_error()?;
	Ok(())
}

#[no_mangle]
pub extern "C" fn request_key_provisioning(
	socket_fd: c_int,
	sign_type: sgx_quote_sign_type_t,
	skip_ra: c_int,
) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let ocall_api = OCallComponentFactory::attestation_api();

	let cfg = match tls_client_config(sign_type, ocall_api, skip_ra == 1) {
		Ok(cfg) => cfg,
		Err(e) => return e,
	};

	let (mut sess, mut conn) = match tls_client_session_stream(socket_fd, cfg) {
		Ok(sc) => (sc),
		Err(e) => return e,
	};

	let mut tls = rustls::Stream::new(&mut sess, &mut conn);

	println!();
	println!("    [Enclave] (MU-RA-Client) MU-RA successful waiting for keys...");

	match receive_files(&mut tls) {
		Ok(_) => println!("    [Enclave] (MU-RA-Client) Registration procedure successful!\n"),
		Err(e) => return e.into(),
	}

	sgx_status_t::SGX_SUCCESS
}

fn receive_files(tls: &mut Stream<ClientSession, TcpStream>) -> EnclaveResult<()> {
	let mut key_len_arr = [0u8; 8];

	let key_len = tls
		.read(&mut key_len_arr)
		.map(|_| usize::from_le_bytes(key_len_arr))
		.sgx_error_with_log("    [Enclave] (MU-RA-Client) Error receiving shielding key length")?;

	let mut rsa_pair = vec![0u8; key_len];
	tls.read(&mut rsa_pair)
		.map(|_| info!("    [Enclave] Received Shielding key"))
		.sgx_error_with_log("    [Enclave] (MU-RA-Client) Error receiving shielding key")?;

	rsa3072::seal(&rsa_pair)?;

	let mut aes_key = [0u8; 16];
	tls.read(&mut aes_key)
		.map(|_| info!("    [Enclave] (MU-RA-Client)Received AES key: {:?}", &aes_key[..]))
		.sgx_error_with_log("    [Enclave] (MU-RA-Client) Error receiving aes key ")?;

	let mut aes_iv = [0u8; 16];
	tls.read(&mut aes_iv)
		.map(|_| info!("    [Enclave] (MU-RA-Client) Received AES IV: {:?}", &aes_iv[..]))
		.sgx_error_with_log("    [Enclave] (MU-RA-Client) Error receiving aes iv")?;

	Aes::new(aes_key, aes_iv).seal()?;

	println!("    [Enclave] (MU-RA-Client) Successfully received keys.");

	Ok(())
}

fn tls_client_session_stream(
	socket_fd: i32,
	cfg: ClientConfig,
) -> SgxResult<(ClientSession, TcpStream)> {
	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).sgx_error()?;
	let sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
	let conn = TcpStream::new(socket_fd).sgx_error()?;
	Ok((sess, conn))
}

fn tls_client_config<A: EnclaveAttestationOCallApi + 'static>(
	sign_type: sgx_quote_sign_type_t,
	ocall_api: Arc<A>,
	skip_ra: bool,
) -> SgxResult<ClientConfig> {
	let (key_der, cert_der) =
		create_ra_report_and_signature(sign_type, ocall_api.clone(), skip_ra).sgx_error()?;

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
