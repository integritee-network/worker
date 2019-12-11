use std::backtrace::{self, PrintFormat};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::vec::Vec;

use sgx_types::*;

use rustls::{ClientSession, Stream, ClientConfig, ServerConfig, ServerSession};
use log::*;

use crate::attestation::{create_ra_report_and_signature, DEV_HOSTNAME};
use crate::constants::ENCRYPTED_STATE_FILE;
use crate::cert;
use crate::{ocall_read_ipfs, ocall_write_ipfs};
use crate::io;
use crate::rsa3072;
use crate::aes;
use crate::utils::UnwrapOrSgxErrorUnexpected;

struct ClientAuth {
	outdated_ok: bool,
}

impl ClientAuth {
	fn new(outdated_ok: bool) -> ClientAuth {
		ClientAuth { outdated_ok }
	}
}

impl rustls::ClientCertVerifier for ClientAuth {
	fn client_auth_root_subjects(&self) -> rustls::DistinguishedNames {
		rustls::DistinguishedNames::new()
	}

	fn verify_client_cert(&self, _certs: &[rustls::Certificate])
						  -> Result<rustls::ClientCertVerified, rustls::TLSError> {
		info!("client cert: {:?}", _certs);
		// This call will automatically verify cert is properly signed
		match cert::verify_mra_cert(&_certs[0].0) {
			Ok(()) => Ok(rustls::ClientCertVerified::assertion()),
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
				if self.outdated_ok {
					warn!("outdated_ok is set, overriding outdated error");
					Ok(rustls::ClientCertVerified::assertion())
				} else {
					Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
				}
			}
			Err(_) => {
				Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
			}
		}
	}
}

struct ServerAuth {
	outdated_ok: bool
}

impl ServerAuth {
	fn new(outdated_ok: bool) -> ServerAuth {
		ServerAuth { outdated_ok }
	}
}

impl rustls::ServerCertVerifier for ServerAuth {
	fn verify_server_cert(&self,
						  _roots: &rustls::RootCertStore,
						  _certs: &[rustls::Certificate],
						  _hostname: webpki::DNSNameRef,
						  _ocsp: &[u8]) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
		info!("server cert: {:?}", _certs);
		// This call will automatically verify cert is properly signed
		match cert::verify_mra_cert(&_certs[0].0) {
			Ok(()) => {
				Ok(rustls::ServerCertVerified::assertion())
			}
			Err(sgx_status_t::SGX_ERROR_UPDATE_NEEDED) => {
				if self.outdated_ok {
					warn!("outdated_ok is set, overriding outdated error");
					Ok(rustls::ServerCertVerified::assertion())
				} else {
					Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
				}
			}
			Err(_) => {
				Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid))
			}
		}
	}
}


#[no_mangle]
pub unsafe extern "C" fn run_server(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let cfg = match tls_server_config(sign_type) {
		Ok(cfg) => cfg,
		Err(e) => return e,
	};

	let (mut sess, mut conn) = match tls_server_sesssion_stream(socket_fd, cfg) {
		Ok(sc) => sc,
		Err(e) => return e,
	};

	let mut tls = rustls::Stream::new(&mut sess, &mut conn);
	println!("    [Enclave] (MU-RA-Server) MU-RA successful sending keys");

	let (rsa_pair, aes, enc_state) = match read_files_to_send() {
		Ok((r, a, s)) => (r, a, s),
		Err(e) => return e,
	};

	match send_files(&mut tls, &rsa_pair, &aes, &enc_state) {
		Ok(_) => println!("    [Enclave] (MU-RA-Server) Registration procedure successful!\n"),
		Err(e) => return e,
	}

	sgx_status_t::SGX_SUCCESS
}

fn tls_server_sesssion_stream(socket_fd: i32, cfg: ServerConfig) -> SgxResult<(ServerSession, TcpStream)> {
	let sess = rustls::ServerSession::new(&Arc::new(cfg));
	let conn = TcpStream::new(socket_fd).sgx_error()?;
	Ok((sess, conn))
}

fn tls_server_config(sign_type: sgx_quote_sign_type_t) -> SgxResult<ServerConfig> {
	let (key_der, cert_der) = create_ra_report_and_signature(sign_type).sgx_error()?;

	let mut cfg = rustls::ServerConfig::new(Arc::new(ClientAuth::new(true)));
	let mut certs = Vec::new();
	certs.push(rustls::Certificate(cert_der));
	let privkey = rustls::PrivateKey(key_der);
	cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![]).sgx_error()?;
	Ok(cfg)
}

fn read_files_to_send() -> SgxResult<(Vec<u8>, aes::Aes, Vec<u8>)> {
	let shielding_key = rsa3072::unseal_pair().sgx_error()?;
	let aes = aes::read_or_create_sealed().sgx_error()?;
	let rsa_pair = serde_json::to_string(&shielding_key).sgx_error()?;
	let enc_state = io::read_plaintext(ENCRYPTED_STATE_FILE).sgx_error()?;

	let rsa_len = rsa_pair.as_bytes().len();
	info!("Read Shielding Key: {:?}", rsa_len);
	info!("Sending AES key {:?}\nIV: {:?}\n", aes.0, aes.1);

	Ok((rsa_pair.as_bytes().to_vec(), aes, enc_state))
}

fn send_files(tls: &mut Stream<ServerSession, TcpStream>,
			  rsa_pair: &Vec<u8>,
			  aes: &(Vec<u8>, Vec<u8>),
			  enc_state: &Vec<u8>
) -> SgxResult<()> {

	tls.write(&rsa_pair.len().to_le_bytes()).sgx_error()?;
	tls.write(&rsa_pair).sgx_error()?;
	tls.write(&aes.0[..]).sgx_error()?;
	tls.write(&aes.1[..]).sgx_error()?;

	println!("    [Enclave] (MU-RA-Server) Keys sent, writing state to IPFS (= file hosting service)");
	info!("Sending encrypted state length");

	tls.write(&enc_state.len().to_le_bytes()).sgx_error()?;
	if enc_state.is_empty() {
		println!("    [Enclave] (MU-RA-Server) No state has been written yet. Nothing to write to ipfs.");
		println!("    [Enclave] (MU-RA-Server) Registration procedure successful!\n");
		return Ok(());
	}
	let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
	let mut cid_buf: [u8; 46] = [0; 46];
	let res = unsafe {
		ocall_write_ipfs(&mut rt as *mut sgx_status_t,
						 enc_state.as_ptr() as *const u8,
						 enc_state.len() as u32,
						 cid_buf.as_mut_ptr() as *mut u8,
						 cid_buf.len() as u32)
	};

	if res == sgx_status_t::SGX_ERROR_UNEXPECTED || rt == sgx_status_t::SGX_ERROR_UNEXPECTED {
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
	}

	println!("    [Enclave] (MU-RA-Server) Write to IPFS successful, sending storage hash");
	tls.write(&cid_buf).sgx_error()?;
	Ok(())
}

#[no_mangle]
pub extern "C" fn run_client(socket_fd: c_int, sign_type: sgx_quote_sign_type_t) -> sgx_status_t {
	let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short);

	let cfg = match tls_client_config(sign_type) {
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
		Err(e) => return e,
	}

	sgx_status_t::SGX_SUCCESS
}

fn receive_files(tls: &mut Stream<ClientSession, TcpStream>) -> SgxResult<()> {
	let mut key_len_arr = [0u8; 8];

	let key_len = tls.read(&mut key_len_arr)
		.map(|_| usize::from_le_bytes(key_len_arr))
		.sgx_error_with_log("Error receiving shielding key length")?;

	let mut rsa_pair = vec![0u8; key_len];
	tls.read(&mut rsa_pair)
		.map(|_| info!("Received Shielding key"))
		.sgx_error_with_log("Error receiving shielding key")?;

	rsa3072::seal(&rsa_pair)?;

	let mut aes_key = [0u8; 16];
	tls.read(&mut aes_key)
		.map(|_| info!("Received AES key: {:?}", &aes_key[..]))
		.sgx_error_with_log("Error receiving aes key ")?;

	let mut aes_iv = [0u8; 16];
	tls.read(&mut aes_iv)
		.map(|_| info!("Received AES IV: {:?}", &aes_iv[..]))
		.sgx_error_with_log("Error receiving aes iv")?;

	aes::seal(aes_key, aes_iv)?;

	println!("    [Enclave] (MU-RA-Client) Received and stored keys, waiting for storage hash...");

	let mut state_len_arr = [0u8; 8];
	let state_len = tls.read(&mut state_len_arr)
		.map(|_| usize::from_le_bytes(state_len_arr))
		.sgx_error_with_log("Error receiving state length")?;

	if state_len == 0 {
		println!("    [Enclave] (MU-RA-Client) No state has been written yet, nothing to fetch from IPFS");
		println!("    [Enclave] (MU-RA-Client) Registration Procedure successful!\n");
		return Ok(())
	}

	let mut cid = [0u8; 46];
	tls.read(&mut cid)
		.map(|_| info!("Received ipfs CID: {:?}", &cid[..]))
		.sgx_error_with_log("Error receiving ipfs CID")?;

	println!("    [Enclave] (MU-RA-Client) Received IPFS storage hash, reading from IPFS...");

	let mut enc_state = vec![0u8; state_len];
	let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
	let _res = unsafe {
		ocall_read_ipfs(&mut rt as *mut sgx_status_t,
						enc_state.as_mut_ptr(),
						enc_state.len() as u32,
						cid.as_ptr(),
						cid.len() as u32)
	};
	println!("    [Enclave] (MU-RA-Client) Got encrypted state from ipfs: {:?}\n", enc_state);
	io::write_plaintext(&enc_state, ENCRYPTED_STATE_FILE)?;
	println!("    [Enclave] (MU-RA-Client) Successfully read state from IPFS");

	Ok(())
}

fn tls_client_session_stream(socket_fd: i32, cfg: ClientConfig) -> SgxResult<(ClientSession, TcpStream)> {
	let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).sgx_error()?;
	let sess = rustls::ClientSession::new(&Arc::new(cfg), dns_name);
	let conn = TcpStream::new(socket_fd).sgx_error()?;
	Ok((sess, conn))
}

fn tls_client_config(sign_type: sgx_quote_sign_type_t) -> SgxResult<ClientConfig> {

	let (key_der, cert_der) = create_ra_report_and_signature(sign_type).sgx_error()?;

	let mut cfg = rustls::ClientConfig::new();
	let mut certs = Vec::new();
	certs.push(rustls::Certificate(cert_der));
	let privkey = rustls::PrivateKey(key_der);

	cfg.set_single_client_cert(certs, privkey);
	cfg.dangerous().set_certificate_verifier(Arc::new(ServerAuth::new(true)));
	cfg.versions.clear();
	cfg.versions.push(rustls::ProtocolVersion::TLSv1_2);
	Ok(cfg)
}
