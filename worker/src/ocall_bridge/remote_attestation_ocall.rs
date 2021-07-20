/*
    Copyright 2019 Supercomputing Systems AG
    Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::ocall_bridge::bridge_api::{
    OCallBridgeError, OCallBridgeResult, RemoteAttestationBridge,
};
use frame_support::ensure;
use log::*;
use sgx_types::*;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::ptr;

pub struct RemoteAttestationOCall {
    // TODO as a member here we need the e-call API trait, so we can use it instead of making the e-call directly
}

impl RemoteAttestationBridge for RemoteAttestationOCall {
    fn init_quote(&self) -> OCallBridgeResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
        // TODO this translation to unsafe C-API should be moved to the EnclaveApi / ECall API
        let mut ti: sgx_target_info_t = sgx_target_info_t::default();
        let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

        let ret_status = unsafe {
            sgx_init_quote(
                &mut ti as *mut sgx_target_info_t,
                &mut eg as *mut sgx_epid_group_id_t,
            )
        };

        ensure!(
            ret_status == sgx_status_t::SGX_SUCCESS,
            OCallBridgeError::InitQuote(ret_status)
        );

        Ok((ti, eg))
    }

    fn get_ias_socket(&self) -> OCallBridgeResult<i32> {
        let port = 443;
        let hostname = "api.trustedservices.intel.com";

        let addr = lookup_ipv4(hostname, port).map_err(OCallBridgeError::GetIasSocket)?;

        let sock = TcpStream::connect(&addr).map_err(|_| {
            OCallBridgeError::GetIasSocket("[-] Connect tls server failed!".to_string())
        })?;

        Ok(sock.into_raw_fd())
    }

    fn get_quote(
        &self,
        revocation_list: Vec<u8>,
        report: sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        spid: sgx_spid_t,
        quote_nonce: sgx_quote_nonce_t,
    ) -> OCallBridgeResult<(sgx_report_t, Vec<u8>)> {
        let mut real_quote_len: u32 = 0;

        let (p_sig_rl, sig_rl_size) = vec_to_c_pointer_with_len(revocation_list);

        let ret =
            unsafe { sgx_calc_quote_size(p_sig_rl, sig_rl_size, &mut real_quote_len as *mut u32) };

        ensure!(
            ret == sgx_status_t::SGX_SUCCESS,
            OCallBridgeError::GetQuote(ret)
        );

        debug!("    Quote size = {}", real_quote_len);

        let p_report = &report as *const sgx_report_t;
        let p_spid = &spid as *const sgx_spid_t;
        let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;

        let mut qe_report = sgx_report_t::default();
        let p_qe_report = &mut qe_report as *mut sgx_report_t;

        const RET_QUOTE_BUF_LEN: usize = 2048;
        let mut return_quote_buf = [0u8; RET_QUOTE_BUF_LEN];
        let p_quote = return_quote_buf.as_mut_ptr();

        if real_quote_len > RET_QUOTE_BUF_LEN as u32 {
            error!(
                "   effective quote length ({}) exceeds buffer size ({})",
                real_quote_len, RET_QUOTE_BUF_LEN
            );
            return Err(OCallBridgeError::GetQuote(
                sgx_status_t::SGX_ERROR_FAAS_BUFFER_TOO_SHORT,
            ));
        }

        let ret = unsafe {
            sgx_get_quote(
                p_report,
                quote_type,
                p_spid,
                p_nonce,
                p_sig_rl,
                sig_rl_size,
                p_qe_report,
                p_quote as *mut sgx_quote_t,
                real_quote_len,
            )
        };

        ensure!(
            ret == sgx_status_t::SGX_SUCCESS,
            OCallBridgeError::GetQuote(ret)
        );

        Ok((
            qe_report,
            Vec::from(&return_quote_buf[..real_quote_len as usize]),
        ))
    }

    fn get_update_info(
        &self,
        platform_blob: sgx_platform_info_t,
        enclave_trusted: i32,
    ) -> OCallBridgeResult<sgx_update_info_bit_t> {
        let mut update_info: sgx_update_info_bit_t = sgx_update_info_bit_t::default();

        let result = unsafe {
            sgx_report_attestation_status(
                &platform_blob as *const sgx_platform_info_t,
                enclave_trusted,
                &mut update_info as *mut sgx_update_info_bit_t,
            )
        };

        ensure!(
            result == sgx_status_t::SGX_SUCCESS,
            OCallBridgeError::GetUpdateInfo(result)
        );

        Ok(update_info)
    }
}

fn lookup_ipv4(host: &str, port: u16) -> Result<SocketAddr, String> {
    use std::net::ToSocketAddrs;

    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{:?}", e))?;
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return Ok(addr);
        }
    }

    Err("Cannot lookup address".to_string())
}

fn vec_to_c_pointer_with_len<A>(input: Vec<A>) -> (*const A, u32) {
    if input.is_empty() {
        (ptr::null(), 0)
    } else {
        (input.as_ptr(), input.len() as u32)
    }
}
