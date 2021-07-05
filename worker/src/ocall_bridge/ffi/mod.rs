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

use crate::ocall_bridge::bridge_api::RemoteAttestationOCall;
use crate::ocall_bridge::component_factory::{
    OCallBridgeComponentFactory, OCallBridgeComponentFactoryImpl,
};
use log::*;
use sgx_types::{
    c_int, sgx_epid_group_id_t, sgx_platform_info_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
    sgx_report_t, sgx_spid_t, sgx_status_t, sgx_target_info_t, sgx_update_info_bit_t,
};
use std::slice;

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    debug!("    Entering ocall_sgx_init_quote");
    let init_result = OCallBridgeComponentFactoryImpl::get_ra_api().init_quote();

    unsafe {
        *ret_ti = init_result.1;
        *ret_gid = init_result.2;
    }

    init_result.0
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
    debug!("    Entering ocall_get_ias_socket");
    let socket = OCallBridgeComponentFactoryImpl::get_ra_api().get_ias_socket();

    unsafe {
        *ret_fd = socket;
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_get_quote(
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
) -> sgx_status_t {
    debug!("    Entering ocall_get_quote");

    let revocation_list: Vec<u8> =
        unsafe { slice::from_raw_parts(p_sigrl, sigrl_len as usize).to_vec() };

    let report = unsafe { *p_report };
    let spid = unsafe { *p_spid };
    let quote_nonce = unsafe { *p_nonce };

    let get_quote_result = OCallBridgeComponentFactoryImpl::get_ra_api().get_quote(
        revocation_list,
        report,
        quote_type,
        spid,
        quote_nonce,
    );

    let quote = get_quote_result.2;

    if quote.len() as u32 > maxlen {
        return sgx_status_t::SGX_ERROR_FAAS_BUFFER_TOO_SHORT;
    }

    let quote_slice = unsafe { slice::from_raw_parts_mut(p_quote, quote.len()) };
    quote_slice.clone_from_slice(quote.as_slice());

    unsafe {
        *p_qe_report = get_quote_result.1;
        *p_quote_len = quote.len() as u32;
    };

    get_quote_result.0
}

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    p_platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    p_update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
    let platform_blob = unsafe { *p_platform_blob };

    let update_info_result = OCallBridgeComponentFactoryImpl::get_ra_api()
        .get_update_info(platform_blob, enclave_trusted);

    if update_info_result.0 != sgx_status_t::SGX_SUCCESS {
        return update_info_result.0;
    }

    unsafe {
        *p_update_info = update_info_result.1;
    }

    sgx_status_t::SGX_SUCCESS
}
