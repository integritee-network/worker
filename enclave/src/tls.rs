use rustls;
use sgx_tcrypto::*;
use sgx_types::*;

use attestation::create_attestation_report;
use cert;
use std::backtrace::{self, PrintFormat};
use std::io::{Read, Write};
use std::io;
use std::net::TcpStream;
use std::str;
use std::sync::Arc;
use std::vec::Vec;

struct ClientAuth {
	outdated_ok: bool,
}

impl ClientAuth {
	fn new(outdated_ok: bool) -> ClientAuth {
		ClientAuth { outdated_ok: outdated_ok }
	}
}

impl rustls::ClientCertVerifier for ClientAuth {
	fn client_auth_root_subjects(&self) -> rustls::DistinguishedNames {
		rustls::DistinguishedNames::new()
	}

	fn verify_client_cert(&self, _certs: &[rustls::Certificate])
						  -> Result<rustls::ClientCertVerified, rustls::TLSError> {
		println!("client cert: {:?}", _certs);
		// This call will automatically verify cert is properly signed
		match cert::verify_mra_cert(&_certs[0].0) {
			Ok(()) => {
				return Ok(rustls::ClientCertVerified::assertion());
			}
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
				if self.outdated_ok {
					println!("outdated_ok is set, overriding outdated error");
					return Ok(rustls::ClientCertVerified::assertion());
				} else {
					return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
				}
			}
			Err(_) => {
				return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
			}
		}
	}
}

struct ServerAuth {
	outdated_ok: bool
}

impl ServerAuth {
	fn new(outdated_ok: bool) -> ServerAuth {
		ServerAuth { outdated_ok: outdated_ok }
	}
}

impl rustls::ServerCertVerifier for ServerAuth {
	fn verify_server_cert(&self,
						  _roots: &rustls::RootCertStore,
						  _certs: &[rustls::Certificate],
						  _hostname: webpki::DNSNameRef,
						  _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		println!("server cert: {:?}", _certs);
		// This call will automatically verify cert is properly signed
		match cert::verify_mra_cert(&_certs[0].0) {
			Ok(()) => {
				return Ok(rustls::ServerCertVerified::assertion());
			}
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
				if self.outdated_ok {
					println!("outdated_ok is set, overriding outdated error");
					return Ok(rustls::ServerCertVerified::assertion());
				} else {
					return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
				}
			}
			Err(_) => {
				return Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid));
			}
		}
	}
}


#[no_mangle]
pub extern "C" fn run_server(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
	env_logger::init();
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	// Generate Keypair
	let ecc_handle = SgxEccHandle::new();
	let _result = ecc_handle.open();
	let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

	let (attn_report, sig, cert) = match create_attestation_report(&pub_k, sign_type) {
		Ok(r) => r,
		Err(e) => {
			println!("Error in create_attestation_report: {:?}", e);
			return e;
		}
	};
	println!("Created attestation report");
	let payload = attn_report + "|" + &sig + "|" + &cert;
	let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
		Ok(r) => r,
		Err(e) => {
			println!("Error in gen_ecc_cert: {:?}", e);
			return e;
		}
	};
	let _result = ecc_handle.close();


	let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true)));
	let mut certs = Vec::new();
	certs.push(rustls::Certificate(cert_der));
	let privkey = rustls::PrivateKey(key_der);

	cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).unwrap();

	let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
	let mut conn = TcpStream::new(socket_fd).unwrap();

	let mut tls = rustls::Stream::new(&mut sess, &mut conn);
	let mut plaintext = [0u8; 1024]; //Vec::new();
	match tls.read(&mut plaintext) {
		Ok(_) => println!("Client said: {}", str::from_utf8(&plaintext).unwrap()),
		Err(e) => {
			println!("Error in read_to_end: {:?}", e);
			panic!("");
		}
	};

	tls.write("hello back".as_bytes()).unwrap();

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn run_client(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
	env_logger::init();
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	// Generate Keypair
	let ecc_handle = SgxEccHandle::new();
	ecc_handle.open().unwrap();
	let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

	let (attn_report, sig, cert) = match create_attestation_report(&pub_k, sign_type) {
		Ok(r) => r,
		Err(e) => {
			println!("Error in create_attestation_report: {:?}", e);
			return e;
		}
	};

	let payload = attn_report + "|" + &sig + "|" + &cert;

	let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
		Ok(r) => r,
		Err(e) => {
			println!("Error in gen_ecc_cert: {:?}", e);
			return e;
		}
	};
	ecc_handle.close().unwrap();


	let mut cfg = rustls::ClientConfig::new();
	let mut certs = Vec::new();
	certs.push(rustls::Certificate(cert_der));
	let privkey = rustls::PrivateKey(key_der);

	cfg.set_single_client_cert(certs, privkey);
	cfg.dangerous().set_certificate_verifier(Arc::new(ServerAuth::new(true)));
	cfg.versions.clear();
	cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);

	let dns_name = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();
	let mut sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
	let mut conn = TcpStream::new(socket_fd).unwrap();

	let mut tls = rustls::Stream::new(&mut sess, &mut conn);
	tls.write("hello".as_bytes()).unwrap();

	let mut plaintext = Vec::new();
	match tls.read_to_end(&mut plaintext) {
		Ok(_) => {
			println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
		}
		Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
			println!("EOF (tls)");
		}
		Err(e) => println!("Error in read_to_end: {:?}", e),
	}

	sgx_status_t::SGX_SUCCESS
}
