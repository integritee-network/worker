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

use crate::{
	cert, io, ocall::OcallApi, utils::hash_from_slice, Error as EnclaveError,
	Result as EnclaveResult,
};
use codec::Encode;
use core::default::Default;
use itertools::Itertools;
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	files::{RA_API_KEY_FILE, RA_DUMP_CERT_DER_FILE, RA_SPID_FILE},
	node::{REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION, RUNTIME_TRANSACTION_VERSION, TEEREX_MODULE},
};
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;
use sp_core::{blake2_256, Pair};
use std::{
	io::{Read, Write},
	net::TcpStream,
	prelude::v1::*,
	slice, str,
	string::String,
	sync::Arc,
	vec::Vec,
};
use substrate_api_client::compose_extrinsic_offline;

pub const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";

#[cfg(feature = "production")]
pub const SIGRL_SUFFIX: &str = "/sgx/attestation/v4/sigrl/";
#[cfg(feature = "production")]
pub const REPORT_SUFFIX: &str = "/sgx/attestation/v4/report";

#[cfg(not(feature = "production"))]
pub const SIGRL_SUFFIX: &str = "/sgx/dev/attestation/v4/sigrl/";
#[cfg(not(feature = "production"))]
pub const REPORT_SUFFIX: &str = "/sgx/dev/attestation/v4/report";

#[no_mangle]
pub unsafe extern "C" fn get_mrenclave(mrenclave: *mut u8, mrenclave_size: u32) -> sgx_status_t {
	let mrenclave_slice = slice::from_raw_parts_mut(mrenclave, mrenclave_size as usize);

	match OcallApi.get_mrenclave_of_self() {
		Ok(m) => {
			mrenclave_slice.copy_from_slice(&m.m[..]);
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => e,
	}
}

fn parse_response_attn_report(resp: &[u8]) -> EnclaveResult<(String, String, String)> {
	debug!("    [Enclave] Entering parse_response_attn_report");
	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp = httparse::Response::new(&mut headers);
	let result = respp.parse(resp);
	debug!("    [Enclave] respp.parse result {:?}", result);

	log_resp_code(&mut respp.code);

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

fn log_resp_code(resp_code: &mut Option<u16>) {
	let msg: &'static str;
	match resp_code {
		Some(200) => msg = "OK Operation Successful",
		Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
		Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
		Some(500) => msg = "Internal error occurred",
		Some(503) =>
			msg = "Service is currently not able to process the request (due to
			a temporary overloading or maintenance). This is a
			temporary state – the same request can be repeated after
			some time. ",
		_ => {
			error!("DBG:{:?}", resp_code);
			msg = "Unknown error occured"
		},
	}
	debug!("    [Enclave] msg = {}", msg);
}

fn parse_response_sigrl(resp: &[u8]) -> EnclaveResult<Vec<u8>> {
	debug!("    [Enclave] Entering parse_response_sigrl");
	let mut headers = [httparse::EMPTY_HEADER; 16];
	let mut respp = httparse::Response::new(&mut headers);
	let result = respp.parse(resp);
	debug!("    [Enclave] Parse result   {:?}", result);
	debug!("    [Enclave] Parse response {:?}", respp);

	log_resp_code(&mut respp.code);

	let mut len_num: u32 = 0;

	for i in 0..respp.headers.len() {
		let h = respp.headers[i];
		if h.name == "content-length" {
			let len_str =
				String::from_utf8(h.value.to_vec()).map_err(|e| EnclaveError::Other(e.into()))?;
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

pub fn make_ias_client_config() -> rustls::ClientConfig {
	let mut config = rustls::ClientConfig::new();

	config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
	config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> EnclaveResult<Vec<u8>> {
	debug!("    [Enclave] Entering get_sigrl_from_intel. fd = {:?}", fd);
	let config = make_ias_client_config();
	//let sigrl_arg = SigRLArg { group_id : gid };
	//let sigrl_req = sigrl_arg.to_httpreq();
	let ias_key = get_ias_api_key()?;

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

	parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> EnclaveResult<(String, String, String)> {
	debug!("    [Enclave] Entering get_report_from_intel. fd = {:?}", fd);
	let config = make_ias_client_config();
	let encoded_quote = base64::encode(&quote[..]);
	let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

	let ias_key = get_ias_api_key()?;

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

	parse_response_attn_report(&plaintext)
}

fn as_u32_le(array: [u8; 4]) -> u32 {
	u32::from(array[0])
		+ (u32::from(array[1]) << 8)
		+ (u32::from(array[2]) << 16)
		+ (u32::from(array[3]) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report<A: EnclaveAttestationOCallApi>(
	pub_k: &[u8; 32],
	sign_type: sgx_quote_sign_type_t,
	ocall_api: &A,
) -> SgxResult<(String, String, String)> {
	// Workflow:
	// (1) ocall to get the target_info structure (ti) and epid group id (eg)
	// (1.5) get sigrl
	// (2) call sgx_create_report with ti+data, produce an sgx_report_t
	// (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

	// (1) get ti + eg
	let init_quote = ocall_api.sgx_init_quote()?;

	let epid_group_id: sgx_epid_group_id_t = init_quote.1;
	let target_info: sgx_target_info_t = init_quote.0;

	debug!("    [Enclave] EPID group id = {:?}", epid_group_id);

	let eg_num = as_u32_le(epid_group_id);

	// (1.5) get sigrl
	let ias_socket = ocall_api.get_ias_socket()?;

	info!("    [Enclave] ias_sock = {}", ias_socket);

	// Now sigrl_vec is the revocation list, a vec<u8>
	let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_socket, eg_num)?;

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

	let spid: sgx_spid_t = load_spid(RA_SPID_FILE)?;

	let quote_result = ocall_api.get_quote(sigrl_vec, report, sign_type, spid, quote_nonce)?;

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
	let ias_socket = ocall_api.get_ias_socket()?;

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

	let (attn_report, sig, cert) = get_report_from_intel(ias_socket, quote_content)?;
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

fn get_ias_api_key() -> EnclaveResult<String> {
	io::read_to_string(RA_API_KEY_FILE)
		.map(|key| key.trim_end().to_owned())
		.map_err(|e| EnclaveError::Other(e.into()))
}

pub fn create_ra_report_and_signature<A: EnclaveAttestationOCallApi>(
	sign_type: sgx_quote_sign_type_t,
	ocall_api: &A,
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
			match create_attestation_report(&chain_signer.public().0, sign_type, ocall_api) {
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
	let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
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

#[no_mangle]
pub unsafe extern "C" fn perform_ra(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u32,
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	// our certificate is unlinkable
	let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

	let (_key_der, cert_der) = match create_ra_report_and_signature(sign_type, &OcallApi, false) {
		Ok(r) => r,
		Err(e) => return e.into(),
	};

	info!("    [Enclave] Compose extrinsic");
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	//let mut nonce_slice     = slice::from_raw_parts(nonce, nonce_size as usize);
	let url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let signer = match Ed25519Seal::unseal_from_static_file() {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	info!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

	debug!("decoded nonce: {}", *nonce);
	let genesis_hash = hash_from_slice(genesis_hash_slice);
	debug!("decoded genesis_hash: {:?}", genesis_hash_slice);
	debug!("worker url: {}", str::from_utf8(url_slice).unwrap());
	let call = [TEEREX_MODULE, REGISTER_ENCLAVE];

	let xt = compose_extrinsic_offline!(
		signer,
		(call, cert_der.to_vec(), url_slice.to_vec()),
		*nonce,
		Era::Immortal,
		genesis_hash,
		genesis_hash,
		RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION
	);

	let xt_encoded = xt.encode();
	let xt_hash = blake2_256(&xt_encoded);
	debug!("    [Enclave] Encoded extrinsic ( len = {} B), hash {:?}", xt_encoded.len(), xt_hash);

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, xt_encoded) {
		return EnclaveError::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn dump_ra_to_disk() -> sgx_status_t {
	// our certificate is unlinkable
	let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

	let (_key_der, cert_der) = match create_ra_report_and_signature(sign_type, &OcallApi, false) {
		Ok(r) => r,
		Err(e) => return e.into(),
	};

	if let Err(err) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
		error!(
			"    [Enclave] failed to write RA file ({}), status: {:?}",
			RA_DUMP_CERT_DER_FILE, err
		);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}
	info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);

	sgx_status_t::SGX_SUCCESS
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
