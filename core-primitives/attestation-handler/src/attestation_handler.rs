// Copyright 2022 Integritee AG and Supercomputing Systems AG
// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{cert, Error as EnclaveError, Error, Result as EnclaveResult};
use codec::Encode;
use core::{convert::TryInto, default::Default};
use itertools::Itertools;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	files::{RA_API_KEY_FILE, RA_DUMP_CERT_DER_FILE, RA_SPID_FILE},
	worker::MR_ENCLAVE_SIZE,
};
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io as io;
use itp_sgx_io::StaticSealedIO;
use itp_time_utils::now_as_secs;
use log::*;
use sgx_rand::{os, Rng};
use sgx_tcrypto::{rsgx_sha256_slice, SgxEccHandle};
use sgx_tse::{rsgx_create_report, rsgx_verify_report};
use sgx_types::{
	c_int, sgx_epid_group_id_t, sgx_quote_nonce_t, sgx_quote_sign_type_t, sgx_report_data_t,
	sgx_spid_t, sgx_status_t, sgx_target_info_t, SgxResult, *,
};
use sp_core::Pair;
use std::{
	borrow::ToOwned,
	format,
	io::{Read, Write},
	net::TcpStream,
	prelude::v1::*,
	println, str,
	string::{String, ToString},
	sync::Arc,
	vec::Vec,
};

pub const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";

#[cfg(feature = "production")]
pub const SIGRL_SUFFIX: &str = "/sgx/attestation/v4/sigrl/";
#[cfg(feature = "production")]
pub const REPORT_SUFFIX: &str = "/sgx/attestation/v4/report";

#[cfg(not(feature = "production"))]
pub const SIGRL_SUFFIX: &str = "/sgx/dev/attestation/v4/sigrl/";
#[cfg(not(feature = "production"))]
pub const REPORT_SUFFIX: &str = "/sgx/dev/attestation/v4/report";

/// Trait to provide an abstraction to the attestation logic
pub trait AttestationHandler {
	/// Generates an encoded remote attestation certificate.
	/// If skip_ra is set, it will not perform a remote attestation via IAS
	/// but instead generate a mock certificate.
	fn generate_ias_ra_cert(&self, skip_ra: bool) -> EnclaveResult<Vec<u8>>;

	fn generate_dcap_ra_cert(
		&self,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
		skip_ra: bool,
	) -> EnclaveResult<(Vec<u8>, Vec<u8>)>;

	/// Get the measurement register value of the enclave
	fn get_mrenclave(&self) -> EnclaveResult<[u8; MR_ENCLAVE_SIZE]>;

	/// Write the remote attestation report to the disk
	fn dump_ias_ra_cert_to_disk(&self) -> EnclaveResult<()>;

	/// Write the remote attestation report to the disk
	fn dump_dcap_ra_cert_to_disk(
		&self,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
	) -> EnclaveResult<()>;

	/// Create the remote attestation report and encapsulate it in a DER certificate
	/// Returns a pair consisting of (private key DER, certificate DER)
	fn create_ra_report_and_signature(
		&self,
		sign_type: sgx_quote_sign_type_t,
		skip_ra: bool,
	) -> EnclaveResult<(Vec<u8>, Vec<u8>)>;
}

pub struct IntelAttestationHandler<OCallApi> {
	pub(crate) ocall_api: Arc<OCallApi>,
}

impl<OCallApi> AttestationHandler for IntelAttestationHandler<OCallApi>
where
	OCallApi: EnclaveAttestationOCallApi,
{
	fn generate_ias_ra_cert(&self, skip_ra: bool) -> EnclaveResult<Vec<u8>> {
		// Our certificate is unlinkable.
		let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

		// FIXME: should call `create_ra_report_and_signature` in skip_ra mode as well:
		// https://github.com/integritee-network/worker/issues/321.
		let cert_der = if !skip_ra {
			match self.create_ra_report_and_signature(sign_type, skip_ra) {
				Ok((_key_der, cert_der)) => cert_der,
				Err(e) => return Err(e),
			}
		} else {
			self.get_mrenclave()?.encode()
		};

		Ok(cert_der)
	}

	fn get_mrenclave(&self) -> EnclaveResult<[u8; MR_ENCLAVE_SIZE]> {
		match self.ocall_api.get_mrenclave_of_self() {
			Ok(m) => Ok(m.m),
			Err(e) => Err(EnclaveError::Sgx(e)),
		}
	}

	fn dump_ias_ra_cert_to_disk(&self) -> EnclaveResult<()> {
		// our certificate is unlinkable
		let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

		let (_key_der, cert_der) = match self.create_ra_report_and_signature(sign_type, false) {
			Ok(r) => r,
			Err(e) => return Err(e),
		};

		if let Err(err) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
			error!(
				"    [Enclave] failed to write RA file ({}), status: {:?}",
				RA_DUMP_CERT_DER_FILE, err
			);
			return Err(Error::IoError(err))
		}
		info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);
		Ok(())
	}

	fn dump_dcap_ra_cert_to_disk(
		&self,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
	) -> EnclaveResult<()> {
		let (_key_der, cert_der) =
			match self.generate_dcap_ra_cert(quoting_enclave_target_info, quote_size, false) {
				Ok(r) => r,
				Err(e) => return Err(e),
			};

		if let Err(err) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
			error!(
				"    [Enclave] failed to write RA file ({}), status: {:?}",
				RA_DUMP_CERT_DER_FILE, err
			);
			return Err(Error::IoError(err))
		}
		info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);
		Ok(())
	}

	fn create_ra_report_and_signature(
		&self,
		sign_type: sgx_quote_sign_type_t,
		skip_ra: bool,
	) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
		let chain_signer = Ed25519Seal::unseal_from_static_file()?;
		info!("[Enclave Attestation] Ed25519 pub raw : {:?}", chain_signer.public().0);

		info!("    [Enclave] Generate keypair");
		let ecc_handle = SgxEccHandle::new();
		let _result = ecc_handle.open();
		let (prv_k, pub_k) = ecc_handle.create_key_pair()?;
		info!("    [Enclave] Generate ephemeral ECDSA keypair successful");
		debug!("     pubkey X is {:02x}", pub_k.gx.iter().format(""));
		debug!("     pubkey Y is {:02x}", pub_k.gy.iter().format(""));

		let payload = if !skip_ra {
			info!("    [Enclave] Create attestation report");
			let (attn_report, sig, cert) =
				match self.create_attestation_report(&chain_signer.public().0, sign_type) {
					Ok(r) => r,
					Err(e) => {
						error!("    [Enclave] Error in create_attestation_report: {:?}", e);
						return Err(e.into())
					},
				};
			println!("    [Enclave] Create attestation report successful");
			debug!("              attn_report = {:?}", attn_report);
			debug!("              sig         = {:?}", sig);
			debug!("              cert        = {:?}", cert);

			// concat the information
			attn_report + "|" + &sig + "|" + &cert
		} else {
			Default::default()
		};

		// generate an ECC certificate
		info!("    [Enclave] Generate ECC Certificate");
		let (key_der, cert_der) =
			match cert::gen_ecc_cert(&payload.into_bytes(), &prv_k, &pub_k, &ecc_handle) {
				Ok(r) => r,
				Err(e) => {
					error!("    [Enclave] gen_ecc_cert failed: {:?}", e);
					return Err(e.into())
				},
			};

		let _ = ecc_handle.close();
		info!("    [Enclave] Generate ECC Certificate successful");
		Ok((key_der, cert_der))
	}

	fn generate_dcap_ra_cert(
		&self,
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
		skip_ra: bool,
	) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
		let chain_signer = Ed25519Seal::unseal_from_static_file()?;
		info!("[Enclave Attestation] Ed25519 signer pub key: {:?}", chain_signer.public().0);

		let ecc_handle = SgxEccHandle::new();
		let _result = ecc_handle.open();
		let (prv_k, pub_k) = ecc_handle.create_key_pair()?;
		info!("Enclave Attestation] Generated ephemeral ECDSA keypair:");

		let payload = if !skip_ra {
			let qe_quote = match self.retrieve_qe_dcap_quote(
				&chain_signer.public().0,
				quoting_enclave_target_info,
				quote_size,
			) {
				Ok(quote) => quote,
				Err(e) => {
					error!("[Enclave] Error in create_dcap_attestation_report: {:?}", e);
					return Err(e.into())
				},
			};
			// Verify the quote via qve enclave
			self.ecdsa_quote_verification(qe_quote)?
		} else {
			Default::default()
		};

		// generate an ECC certificate
		debug!("[Enclave] Generate ECC Certificate");
		let (key_der, cert_der) = match cert::gen_ecc_cert(&payload, &prv_k, &pub_k, &ecc_handle) {
			Ok(r) => r,
			Err(e) => {
				error!("[Enclave] gen_ecc_cert failed: {:?}", e);
				return Err(e.into())
			},
		};

		let _ = ecc_handle.close();

		Ok((key_der, cert_der))
	}
}

impl<OCallApi> IntelAttestationHandler<OCallApi>
where
	OCallApi: EnclaveAttestationOCallApi,
{
	pub fn new(ocall_api: Arc<OCallApi>) -> Self {
		Self { ocall_api }
	}

	fn parse_response_attn_report(&self, resp: &[u8]) -> EnclaveResult<(String, String, String)> {
		debug!("    [Enclave] Entering parse_response_attn_report");
		let mut headers = [httparse::EMPTY_HEADER; 16];
		let mut respp = httparse::Response::new(&mut headers);
		let result = respp.parse(resp);
		debug!("    [Enclave] respp.parse result {:?}", result);

		self.log_resp_code(&mut respp.code);

		let mut len_num: u32 = 0;

		let mut sig = String::new();
		let mut cert = String::new();
		let mut attn_report = String::new();

		for i in 0..respp.headers.len() {
			let h = respp.headers[i];
			//println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
			match h.name {
				"Content-Length" => {
					let len_str = String::from_utf8(h.value.to_vec())
						.map_err(|e| EnclaveError::Other(e.into()))?;
					len_num = len_str.parse::<u32>().map_err(|e| EnclaveError::Other(e.into()))?;
					debug!("    [Enclave] Content length = {}", len_num);
				},
				"X-IASReport-Signature" =>
					sig = String::from_utf8(h.value.to_vec())
						.map_err(|e| EnclaveError::Other(e.into()))?,
				"X-IASReport-Signing-Certificate" =>
					cert = String::from_utf8(h.value.to_vec())
						.map_err(|e| EnclaveError::Other(e.into()))?,
				_ => (),
			}
		}

		// Remove %0A from cert, and only obtain the signing cert
		cert = cert.replace("%0A", "");
		cert = cert::percent_decode(cert)?;
		let v: Vec<&str> = cert.split("-----").collect();
		let sig_cert = v[2].to_string();

		if len_num != 0 {
			// The unwrap is safe. It resolves to the https::Status' unwrap function which only panics
			// if the the response is not complete, which cannot happen if the result is Ok().
			let header_len = result.map_err(|e| EnclaveError::Other(e.into()))?.unwrap();
			let resp_body = &resp[header_len..];
			attn_report =
				String::from_utf8(resp_body.to_vec()).map_err(|e| EnclaveError::Other(e.into()))?;
			debug!("    [Enclave] Attestation report = {}", attn_report);
		}

		// len_num == 0
		Ok((attn_report, sig, sig_cert))
	}

	fn log_resp_code(&self, resp_code: &mut Option<u16>) {
		let msg = match resp_code {
			Some(200) => "OK Operation Successful",
			Some(401) => "Unauthorized Failed to authenticate or authorize request.",
			Some(404) => "Not Found GID does not refer to a valid EPID group ID.",
			Some(500) => "Internal error occurred",
			Some(503) =>
				"Service is currently not able to process the request (due to
			a temporary overloading or maintenance). This is a
			temporary state – the same request can be repeated after
			some time. ",
			_ => {
				error!("DBG:{:?}", resp_code);
				"Unknown error occured"
			},
		};
		debug!("    [Enclave] msg = {}", msg);
	}

	fn parse_response_sigrl(&self, resp: &[u8]) -> EnclaveResult<Vec<u8>> {
		debug!("    [Enclave] Entering parse_response_sigrl");
		let mut headers = [httparse::EMPTY_HEADER; 16];
		let mut respp = httparse::Response::new(&mut headers);
		let result = respp.parse(resp);
		debug!("    [Enclave] Parse result   {:?}", result);
		debug!("    [Enclave] Parse response {:?}", respp);

		self.log_resp_code(&mut respp.code);

		let mut len_num: u32 = 0;

		for i in 0..respp.headers.len() {
			let h = respp.headers[i];
			if h.name == "content-length" {
				let len_str = String::from_utf8(h.value.to_vec())
					.map_err(|e| EnclaveError::Other(e.into()))?;
				len_num = len_str.parse::<u32>().map_err(|e| EnclaveError::Other(e.into()))?;
				debug!("    [Enclave] Content length = {}", len_num);
			}
		}

		if len_num != 0 {
			// The unwrap is safe. It resolves to the https::Status' unwrap function which only panics
			// if the the response is not complete, which cannot happen if the result is Ok().
			let header_len = result.map_err(|e| EnclaveError::Other(e.into()))?.unwrap();
			let resp_body = &resp[header_len..];
			debug!("    [Enclave] Base64-encoded SigRL: {:?}", resp_body);

			let resp_str = str::from_utf8(resp_body).map_err(|e| EnclaveError::Other(e.into()))?;
			return base64::decode(resp_str).map_err(|e| EnclaveError::Other(e.into()))
		}

		// len_num == 0
		Ok(Vec::new())
	}

	fn make_ias_client_config() -> rustls::ClientConfig {
		let mut config = rustls::ClientConfig::new();

		config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
		config
	}

	fn get_sigrl_from_intel(&self, fd: c_int, gid: u32) -> EnclaveResult<Vec<u8>> {
		debug!("    [Enclave] Entering get_sigrl_from_intel. fd = {:?}", fd);
		let config = Self::make_ias_client_config();
		//let sigrl_arg = SigRLArg { group_id : gid };
		//let sigrl_req = sigrl_arg.to_httpreq();
		let ias_key = Self::get_ias_api_key()?;

		let req = format!("GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
						  SIGRL_SUFFIX,
						  gid,
						  DEV_HOSTNAME,
						  ias_key);
		debug!("    [Enclave]  request = {}", req);

		let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME)
			.map_err(|e| EnclaveError::Other(e.into()))?;
		let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
		let mut sock = TcpStream::new(fd)?;
		let mut tls = rustls::Stream::new(&mut sess, &mut sock);

		let _result = tls.write(req.as_bytes());
		let mut plaintext = Vec::new();

		debug!("    [Enclave] tls.write complete");

		tls.read_to_end(&mut plaintext)?;

		debug!("    [Enclave] tls.read_to_end complete");
		let resp_string =
			String::from_utf8(plaintext.clone()).map_err(|e| EnclaveError::Other(e.into()))?;

		debug!("    [Enclave] resp_string = {}", resp_string);

		self.parse_response_sigrl(&plaintext)
	}

	// TODO: support pse
	fn get_report_from_intel(
		&self,
		fd: c_int,
		quote: Vec<u8>,
	) -> EnclaveResult<(String, String, String)> {
		debug!("    [Enclave] Entering get_report_from_intel. fd = {:?}", fd);
		let config = Self::make_ias_client_config();
		let encoded_quote = base64::encode(&quote[..]);
		let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

		let ias_key = Self::get_ias_api_key()?;

		let req = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
						  REPORT_SUFFIX,
						  DEV_HOSTNAME,
						  ias_key,
						  encoded_json.len(),
						  encoded_json);
		debug!("    [Enclave] Req = {}", req);
		let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).map_err(|e| {
			error!("Invalid DEV_HOSTNAME");
			EnclaveError::Other(e.into())
		})?;
		let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
		let mut sock = TcpStream::new(fd)?;
		let mut tls = rustls::Stream::new(&mut sess, &mut sock);

		let _result = tls.write(req.as_bytes());
		let mut plaintext = Vec::new();

		debug!("    [Enclave] tls.write complete");

		tls.read_to_end(&mut plaintext)?;
		debug!("    [Enclave] tls.read_to_end complete");
		let resp_string = String::from_utf8(plaintext.clone()).map_err(|e| {
			error!("    [Enclave] error decoding tls answer to string");
			EnclaveError::Other(e.into())
		})?;

		debug!("    [Enclave] resp_string = {}", resp_string);

		self.parse_response_attn_report(&plaintext)
	}

	fn as_u32_le(&self, array: [u8; 4]) -> u32 {
		u32::from(array[0])
			+ (u32::from(array[1]) << 8)
			+ (u32::from(array[2]) << 16)
			+ (u32::from(array[3]) << 24)
	}

	fn create_attestation_report(
		&self,
		pub_k: &[u8; 32],
		sign_type: sgx_quote_sign_type_t,
	) -> SgxResult<(String, String, String)> {
		// Workflow:
		// (1) ocall to get the target_info structure (ti) and epid group id (eg)
		// (1.5) get sigrl
		// (2) call sgx_create_report with ti+data, produce an sgx_report_t
		// (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

		// (1) get ti + eg
		let init_quote = self.ocall_api.sgx_init_quote()?;

		let epid_group_id: sgx_epid_group_id_t = init_quote.1;
		let target_info: sgx_target_info_t = init_quote.0;

		debug!("    [Enclave] EPID group id = {:?}", epid_group_id);

		let eg_num = self.as_u32_le(epid_group_id);

		// (1.5) get sigrl
		let ias_socket = self.ocall_api.get_ias_socket()?;

		info!("    [Enclave] ias_sock = {}", ias_socket);

		// Now sigrl_vec is the revocation list, a vec<u8>
		let sigrl_vec: Vec<u8> = self.get_sigrl_from_intel(ias_socket, eg_num)?;

		// (2) Generate the report
		let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
		report_data.d[..32].clone_from_slice(&pub_k[..]);

		let report = match rsgx_create_report(&target_info, &report_data) {
			Ok(r) => {
				debug!(
					"    [Enclave] Report creation successful. mr_signer.m = {:x?}",
					r.body.mr_signer.m
				);
				r
			},
			Err(e) => {
				error!("    [Enclave] Report creation failed. {:?}", e);
				return Err(e)
			},
		};

		let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
		let mut os_rng = os::SgxRng::new().map_err(|e| EnclaveError::Other(e.into()))?;
		os_rng.fill_bytes(&mut quote_nonce.rand);

		// (3) Generate the quote
		// Args:
		//       1. sigrl: ptr + len
		//       2. report: ptr 432bytes
		//       3. linkable: u32, unlinkable=0, linkable=1
		//       4. spid: sgx_spid_t ptr 16bytes
		//       5. sgx_quote_nonce_t ptr 16bytes
		//       6. p_sig_rl + sigrl size ( same to sigrl)
		//       7. [out]p_qe_report need further check
		//       8. [out]p_quote
		//       9. quote_size

		let spid: sgx_spid_t = Self::load_spid(RA_SPID_FILE)?;

		let quote_result =
			self.ocall_api.get_quote(sigrl_vec, report, sign_type, spid, quote_nonce)?;

		let qe_report = quote_result.0;
		let quote_content = quote_result.1;

		// Added 09-28-2018
		// Perform a check on qe_report to verify if the qe_report is valid
		match rsgx_verify_report(&qe_report) {
			Ok(()) => debug!("    [Enclave] rsgx_verify_report success!"),
			Err(x) => {
				error!("    [Enclave] rsgx_verify_report failed. {:?}", x);
				return Err(x)
			},
		}

		// Check if the qe_report is produced on the same platform
		if target_info.mr_enclave.m != qe_report.body.mr_enclave.m
			|| target_info.attributes.flags != qe_report.body.attributes.flags
			|| target_info.attributes.xfrm != qe_report.body.attributes.xfrm
		{
			error!("    [Enclave] qe_report does not match current target_info!");
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		debug!("    [Enclave] qe_report check success");

		// Check qe_report to defend against replay attack
		// The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
		// it received is not modified by the untrusted SW stack, and not a replay.
		// The implementation in QE is to generate a REPORT targeting the ISV
		// enclave (target info from p_report) , with the lower 32Bytes in
		// report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
		// p_qe_report and report.data to confirm the QUOTE has not be modified and
		// is not a replay. It is optional.

		// need to call this a second time (first time is when we get the sigrl revocation list)
		// (has some internal state that needs to be reset)!
		let ias_socket = self.ocall_api.get_ias_socket()?;

		let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
		rhs_vec.extend(&quote_content);
		let rhs_hash = rsgx_sha256_slice(&rhs_vec[..])?;
		let lhs_hash = &qe_report.body.report_data.d[..32];

		debug!("    [Enclave] rhs hash = {:02X}", rhs_hash.iter().format(""));
		debug!("    [Enclave] lhs hash = {:02X}", lhs_hash.iter().format(""));

		if rhs_hash != lhs_hash {
			error!("    [Enclave] Quote is tampered!");
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		let (attn_report, sig, cert) = self.get_report_from_intel(ias_socket, quote_content)?;
		Ok((attn_report, sig, cert))
	}

	fn load_spid(filename: &str) -> SgxResult<sgx_spid_t> {
		match io::read_to_string(filename).map(|contents| decode_spid(&contents)) {
			Ok(r) => r,
			Err(e) => {
				error!("Failed to load SPID: {:?}", e);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			},
		}
	}

	fn get_ias_api_key() -> EnclaveResult<String> {
		io::read_to_string(RA_API_KEY_FILE)
			.map(|key| key.trim_end().to_owned())
			.map_err(|e| EnclaveError::Other(e.into()))
	}

	pub fn ecdsa_quote_verification(&self, quote: Vec<u8>) -> SgxResult<Vec<u8>> {
		let mut app_enclave_target_info: sgx_target_info_t = unsafe { std::mem::zeroed() };
		let quote_collateral: sgx_ql_qve_collateral_t = unsafe { std::mem::zeroed() };
		let mut qve_report_info: sgx_ql_qe_report_info_t = unsafe { std::mem::zeroed() };
		let supplemental_data_size = std::mem::size_of::<sgx_ql_qv_supplemental_t>() as u32;

		// Get target info of the app enclave. QvE will target the generated report to this enclave.
		let ret_val =
			unsafe { sgx_self_target(&mut app_enclave_target_info as *mut sgx_target_info_t) };
		if ret_val != sgx_status_t::SGX_SUCCESS {
			error!("sgx_self_target returned: {:?}", ret_val);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		// Set current time, which is needed to check against the expiration date of the certificate.
		let current_time: i64 = now_as_secs().try_into().unwrap_or_else(|e| {
			panic!("Could not convert SystemTime from u64 into i64: {:?}", e);
		});

		// Set random nonce.
		let mut rand_nonce = vec![0u8; 16];
		let ret_val = unsafe { sgx_read_rand(rand_nonce.as_mut_ptr(), rand_nonce.len()) };
		if ret_val != sgx_status_t::SGX_SUCCESS {
			error!("sgx_read_rand returned: {:?}", ret_val);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}
		debug!("Retrieved random nonce {:?}", rand_nonce);
		qve_report_info.nonce.rand.copy_from_slice(rand_nonce.as_slice());
		qve_report_info.app_enclave_target_info = app_enclave_target_info;

		// Ocall to call Quote verification Enclave (QvE), which verifies the generated quote.
		let (
			collateral_expiration_status,
			quote_verification_result,
			qve_report_info_return_value,
			supplemental_data,
		) = self.ocall_api.get_qve_report_on_quote(
			quote.clone(),
			current_time,
			quote_collateral,
			qve_report_info,
			supplemental_data_size,
		)?;

		// Check nonce of qve report to protect against replay attacks, as the qve report
		// is coming from the untrusted side.
		if qve_report_info_return_value.nonce.rand != qve_report_info.nonce.rand {
			error!(
				"Nonce of input value and return value are not matching. Input: {:?}, Output: {:?}",
				qve_report_info.nonce.rand, qve_report_info_return_value.nonce.rand
			);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		// Set the threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
		// e.g. You can check latest QvE ISVSVN from QvE configuration file on Github
		// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Enclave/linux/config.xml#L4
		// or you can get latest QvE ISVSVN in QvE Identity JSON file from
		// https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity
		// Make sure you are using trusted & latest QvE ISV SVN as threshold
		// Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
		let qve_isvsvn_threshold: sgx_isv_svn_t = 6;

		// Verify the qve report to validate that it is coming from a legit quoting verification enclave
		// and has not been tampered with.
		let ret_val = unsafe {
			sgx_tvl_verify_qve_report_and_identity(
				quote.as_ptr(),
				quote.len() as u32,
				&qve_report_info_return_value as *const sgx_ql_qe_report_info_t,
				current_time,
				collateral_expiration_status,
				quote_verification_result,
				supplemental_data.as_ptr(),
				supplemental_data_size,
				qve_isvsvn_threshold,
			)
		};

		if ret_val != sgx_quote3_error_t::SGX_QL_SUCCESS {
			error!("sgx_tvl_verify_qve_report_and_identity returned: {:?}", ret_val);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		// TODO. What to send to our teerex pallet?
		Ok(vec![])
	}

	pub fn retrieve_qe_dcap_quote(
		&self,
		pub_k: &[u8; 32],
		quoting_enclave_target_info: &sgx_target_info_t,
		quote_size: u32,
	) -> SgxResult<Vec<u8>> {
		// Generate app enclave report and include the enclave public key.
		// The quote will be generated on top of this report and validate that the
		// report as well as the public key inside it are coming from a legit
		// intel sgx enclave.
		let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
		report_data.d[..32].clone_from_slice(&pub_k[..]);

		let app_report = match rsgx_create_report(quoting_enclave_target_info, &report_data) {
			Ok(report) => {
				debug!(
					"rsgx_create_report creation successful. mr_signer: {:?}",
					report.body.mr_signer.m
				);
				report
			},
			Err(e) => {
				error!("rsgx_create_report creation failed. {:?}", e);
				return Err(e)
			},
		};

		// Retrieve quote from pccs for our app enclave.
		debug!("Entering ocall_api.get_dcap_quote with quote size: {:?} ", quote_size);
		let quote_vec = self.ocall_api.get_dcap_quote(app_report, quote_size)?;

		// Check mrenclave of quote, to ensure the quote has not been tampered with
		// while being on the untrusted side.
		// This step is probably obsolete, as the QvE will check the quote as well on behalf
		// of the target enclave.
		let p_quote3: *const sgx_quote3_t = quote_vec.as_ptr() as *const sgx_quote3_t;
		let quote3: sgx_quote3_t = unsafe { *p_quote3 };
		if quote3.report_body.mr_enclave.m != app_report.body.mr_enclave.m {
			error!("mr_enclave of quote and app_report are not matching");
			error!("mr_enclave of quote: {:?}", quote3.report_body.mr_enclave.m);
			error!("mr_enclave of quote: {:?}", app_report.body.mr_enclave.m);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		Ok(quote_vec)
	}
}

fn decode_spid(hex_encoded_string: &str) -> SgxResult<sgx_spid_t> {
	let mut spid = sgx_spid_t::default();
	let hex = hex_encoded_string.trim();

	if hex.len() < itp_settings::files::SPID_MIN_LENGTH {
		error!(
			"Input spid length ({}) is incorrect, minimum length required is {}",
			hex.len(),
			itp_settings::files::SPID_MIN_LENGTH
		);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	let decoded_vec = hex::decode(hex).map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

	spid.id.copy_from_slice(&decoded_vec[..16]);
	Ok(spid)
}

#[cfg(feature = "test")]
pub mod tests {

	use super::*;

	pub fn decode_spid_works() {
		let spid_encoded = "F39ABCF95015A5BF6C7D360EF5035E12";
		let expected_spid = sgx_spid_t {
			id: [243, 154, 188, 249, 80, 21, 165, 191, 108, 125, 54, 14, 245, 3, 94, 18],
		};

		let decoded_spid = decode_spid(spid_encoded).unwrap();
		assert_eq!(decoded_spid.id, expected_spid.id);
	}
}
