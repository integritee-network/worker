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

use std::io::{Read, Write};
use std::net::TcpStream;
use std::prelude::v1::*;
use std::ptr;
use std::slice;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::vec::Vec;

use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;

use codec::Encode;
use core::default::Default;
use itertools::Itertools;
use log::*;
use sp_core::Pair;
use substrate_api_client::compose_extrinsic_offline;

use crate::constants::{
    RA_API_KEY_FILE, RA_DUMP_CERT_DER_FILE, RA_SPID_FILE, REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION,
    SUBSRATEE_REGISTRY_MODULE,
};
use crate::ed25519;
use crate::io;
use crate::utils::{hash_from_slice, write_slice_and_whitespace_pad, UnwrapOrSgxErrorUnexpected};
use crate::{cert, hex};

pub const DEV_HOSTNAME: &str = "api.trustedservices.intel.com";

#[cfg(feature = "production")]
pub const SIGRL_SUFFIX: &str = "/sgx/attestation/v3/sigrl/";
#[cfg(feature = "production")]
pub const REPORT_SUFFIX: &str = "/sgx/attestation/v3/report";

#[cfg(not(feature = "production"))]
pub const SIGRL_SUFFIX: &str = "/sgx/dev/attestation/v3/sigrl/";
#[cfg(not(feature = "production"))]
pub const REPORT_SUFFIX: &str = "/sgx/dev/attestation/v3/report";

extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

#[no_mangle]
pub unsafe extern "C" fn get_mrenclave(mrenclave: *mut u8, mrenclave_size: u32) -> sgx_status_t {
    let mrenclave_slice = slice::from_raw_parts_mut(mrenclave, mrenclave_size as usize);
    match get_mrenclave_of_self() {
        Ok(m) => {
            mrenclave_slice.copy_from_slice(&m.m[..]);
            sgx_status_t::SGX_SUCCESS
        }
        Err(e) => e,
    }
}

pub fn get_mrenclave_of_self() -> SgxResult<sgx_measurement_t> {
    Ok(get_report_of_self()?.mr_enclave)
}

fn get_report_of_self() -> SgxResult<sgx_report_body_t> {
    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    debug!("    [Enclave] EPID group id = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let report_data: sgx_report_data_t = sgx_report_data_t::default();

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            debug!(
                "    [Enclave] Report creation successful. mr_signer.m = {:?}",
                r.body.mr_signer.m
            );
            r
        }
        Err(e) => {
            error!("    [Enclave] Report creation failed. {:?}", e);
            return Err(e);
        }
    };
    Ok(rep.body)
}

fn parse_response_attn_report(resp: &[u8]) -> SgxResult<(String, String, String)> {
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
                let len_str = String::from_utf8(h.value.to_vec()).sgx_error()?;
                len_num = len_str.parse::<u32>().sgx_error()?;
                debug!("    [Enclave] Content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = String::from_utf8(h.value.to_vec()).sgx_error()?,
            "X-IASReport-Signing-Certificate" => {
                cert = String::from_utf8(h.value.to_vec()).sgx_error()?
            }
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
        let header_len = result.sgx_error()?.unwrap();
        let resp_body = &resp[header_len..];
        attn_report = String::from_utf8(resp_body.to_vec()).sgx_error()?;
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
        Some(503) => {
            msg = "Service is currently not able to process the request (due to
			a temporary overloading or maintenance). This is a
			temporary state – the same request can be repeated after
			some time. "
        }
        _ => {
            error!("DBG:{:?}", resp_code);
            msg = "Unknown error occured"
        }
    }
    debug!("    [Enclave] msg = {}", msg);
}

fn parse_response_sigrl(resp: &[u8]) -> SgxResult<Vec<u8>> {
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
            let len_str = String::from_utf8(h.value.to_vec()).sgx_error()?;
            len_num = len_str.parse::<u32>().sgx_error()?;
            debug!("    [Enclave] Content length = {}", len_num);
        }
    }

    if len_num != 0 {
        // The unwrap is safe. It resolves to the https::Status' unwrap function which only panics
        // if the the response is not complete, which cannot happen if the result is Ok().
        let header_len = result.sgx_error()?.unwrap();
        let resp_body = &resp[header_len..];
        debug!("    [Enclave] Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).sgx_error()?).sgx_error();
    }

    // len_num == 0
    Ok(Vec::new())
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config
}

pub fn get_sigrl_from_intel(fd: c_int, gid: u32) -> SgxResult<Vec<u8>> {
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

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).sgx_error()?;
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).sgx_error()?;
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    debug!("    [Enclave] tls.write complete");

    tls.read_to_end(&mut plaintext)
        .sgx_error_with_log("    [Enclave] tls.read_to_end")?;

    debug!("    [Enclave] tls.read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).sgx_error()?;

    debug!("    [Enclave] resp_string = {}", resp_string);

    parse_response_sigrl(&plaintext)
}

// TODO: support pse
pub fn get_report_from_intel(fd: c_int, quote: Vec<u8>) -> SgxResult<(String, String, String)> {
    debug!(
        "    [Enclave] Entering get_report_from_intel. fd = {:?}",
        fd
    );
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
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME)
        .sgx_error_with_log("Invalid DEV_HOSTNAME")?;
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).sgx_error()?;
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    debug!("    [Enclave] tls.write complete");

    tls.read_to_end(&mut plaintext).sgx_error()?;
    debug!("    [Enclave] tls.read_to_end complete");
    let resp_string = String::from_utf8(plaintext.clone()).sgx_error()?;

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
pub fn create_attestation_report(
    pub_k: &[u8; 32],
    sign_type: sgx_quote_sign_type_t,
) -> SgxResult<(String, String, String)> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    debug!("    [Enclave] EPID group id = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = 0;

    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    info!("    [Enclave] ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_sock, eg_num)?;

    // (2) Generate the report
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    report_data.d[..32].clone_from_slice(&pub_k[..]);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            debug!(
                "    [Enclave] Report creation successful. mr_signer.m = {:x?}",
                r.body.mr_signer.m
            );
            r
        }
        Err(e) => {
            error!("    [Enclave] Report creation failed. {:?}", e);
            return Err(e);
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().sgx_error()?;
    os_rng.fill_bytes(&mut quote_nonce.rand);
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

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
    let (p_sigrl, sigrl_len) = if sigrl_vec.is_empty() {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };
    let p_report = &rep as *const sgx_report_t;
    let quote_type = sign_type;

    let spid: sgx_spid_t = load_spid(RA_SPID_FILE)?;

    let p_spid = &spid as *const sgx_spid_t;
    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_qe_report,
            p_quote,
            maxlen,
            p_quote_len,
        )
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        error!("    [Enclave] ocall_get_quote failed. {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => debug!("    [Enclave] rsgx_verify_report success!"),
        Err(x) => {
            error!("    [Enclave] rsgx_verify_report failed. {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        error!("    [Enclave] qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
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

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..])?;
    let lhs_hash = &qe_report.body.report_data.d[..32];

    debug!(
        "    [Enclave] rhs hash = {:02X}",
        rhs_hash.iter().format("")
    );
    debug!(
        "    [Enclave] lhs hash = {:02X}",
        lhs_hash.iter().format("")
    );

    if rhs_hash != lhs_hash {
        error!("    [Enclave] Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_sock, quote_vec)?;
    Ok((attn_report, sig, cert))
}

fn load_spid(filename: &str) -> SgxResult<sgx_spid_t> {
    io::read_to_string(filename)
        .map(|contents| hex::decode_spid(&contents))
        .sgx_error()?
}

fn get_ias_api_key() -> SgxResult<String> {
    io::read_to_string(RA_API_KEY_FILE).map(|key| key.trim_end().to_owned())
}

pub fn create_ra_report_and_signature(
    sign_type: sgx_quote_sign_type_t,
) -> SgxResult<(Vec<u8>, Vec<u8>)> {
    let chain_signer = ed25519::unseal_pair()?;
    info!(
        "[Enclave Attestation] Ed25519 pub raw : {:?}",
        chain_signer.public().0
    );

    info!("    [Enclave] Generate keypair");
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair()?;
    info!("    [Enclave] Generate ephemeral ECDSA keypair successful");
    debug!("     pubkey X is {:02x}", pub_k.gx.iter().format(""));
    debug!("     pubkey Y is {:02x}", pub_k.gy.iter().format(""));

    info!("    [Enclave] Create attestation report");
    let (attn_report, sig, cert) =
        match create_attestation_report(&chain_signer.public().0, sign_type) {
            Ok(r) => r,
            Err(e) => {
                error!("    [Enclave] Error in create_attestation_report: {:?}", e);
                return Err(e);
            }
        };
    println!("    [Enclave] Create attestation report successful");
    debug!("              attn_report = {:?}", attn_report);
    debug!("              sig         = {:?}", sig);
    debug!("              cert        = {:?}", cert);

    // concat the information
    let payload = attn_report + "|" + &sig + "|" + &cert;

    // generate an ECC certificate
    info!("    [Enclave] Generate ECC Certificate");
    let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            error!("    [Enclave] gen_ecc_cert failed: {:?}", e);
            return Err(e);
        }
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
    url: *const u8,
    url_size: u32,
    unchecked_extrinsic: *mut u8,
    unchecked_extrinsic_size: u32,
) -> sgx_status_t {
    // our certificate is unlinkable
    let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

    let (_key_der, cert_der) = match create_ra_report_and_signature(sign_type) {
        Ok(r) => r,
        Err(e) => return e,
    };

    info!("    [Enclave] Compose extrinsic");
    let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
    //let mut nonce_slice     = slice::from_raw_parts(nonce, nonce_size as usize);
    let url_slice = slice::from_raw_parts(url, url_size as usize);
    let extrinsic_slice =
        slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    info!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

    debug!("decoded nonce: {}", *nonce);
    let genesis_hash = hash_from_slice(genesis_hash_slice);
    debug!("decoded genesis_hash: {:?}", genesis_hash_slice);
    debug!("worker url: {}", str::from_utf8(url_slice).unwrap());
    let call = [SUBSRATEE_REGISTRY_MODULE, REGISTER_ENCLAVE];

    let xt = compose_extrinsic_offline!(
        signer,
        (call, cert_der.to_vec(), url_slice.to_vec()),
        *nonce,
        genesis_hash,
        RUNTIME_SPEC_VERSION
    );

    let encoded = xt.encode();
    debug!("    [Enclave] Encoded extrinsic = {:?}", encoded);

    write_slice_and_whitespace_pad(extrinsic_slice, encoded);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn dump_ra_to_disk() -> sgx_status_t {
    // our certificate is unlinkable
    let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

    let (_key_der, cert_der) = match create_ra_report_and_signature(sign_type) {
        Ok(r) => r,
        Err(e) => return e,
    };

    if let Err(status) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
        return status;
    }
    info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);

    sgx_status_t::SGX_SUCCESS
}
