/*
	Copyright 2019 Supercomputing Systems AG

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

use crate::ocall::{ffi, ocall_api::EnclaveAttestationOCallApi};
use sgx_types::{
	sgx_epid_group_id_t, sgx_quote_nonce_t, sgx_quote_sign_type_t, sgx_report_t, sgx_spid_t,
	sgx_status_t, sgx_target_info_t,
};
use std::{ptr, vec::Vec};

pub struct EnclaveAttestationOCallApiImpl {}

impl EnclaveAttestationOCallApiImpl {
	const RET_QUOTE_BUF_LEN: usize = 2048;
}

impl EnclaveAttestationOCallApi for EnclaveAttestationOCallApiImpl {
	fn ocall_sgx_init_quote(&self) -> (sgx_status_t, sgx_target_info_t, sgx_epid_group_id_t) {
		let mut ti: sgx_target_info_t = sgx_target_info_t::default();
		let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let res = unsafe {
			ffi::ocall_sgx_init_quote(
				&mut rt as *mut sgx_status_t,
				&mut ti as *mut sgx_target_info_t,
				&mut eg as *mut sgx_epid_group_id_t,
			)
		};

		let consolidated_status = consolidate_sgx_status(res, rt);

		(consolidated_status, ti, eg)
	}

	fn ocall_get_ias_socket(&self) -> (sgx_status_t, i32) {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut ias_sock: i32 = 0;

		let res = unsafe {
			ffi::ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
		};

		let consolidated_status = consolidate_sgx_status(res, rt);

		(consolidated_status, ias_sock)
	}

	fn ocall_get_quote(
		&self,
		sig_rl: Vec<u8>,
		report: sgx_report_t,
		sign_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> (sgx_status_t, sgx_report_t, Vec<u8>) {
		let mut qe_report = sgx_report_t::default();
		let mut return_quote_buf = [0u8; EnclaveAttestationOCallApiImpl::RET_QUOTE_BUF_LEN];
		let mut quote_len: u32 = 0;

		let (p_sigrl, sigrl_len) = if sig_rl.is_empty() {
			(ptr::null(), 0)
		} else {
			(sig_rl.as_ptr(), sig_rl.len() as u32)
		};
		let p_report = &report as *const sgx_report_t;
		let quote_type = sign_type;

		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let p_spid = &spid as *const sgx_spid_t;
		let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
		let p_qe_report = &mut qe_report as *mut sgx_report_t;
		let p_quote = return_quote_buf.as_mut_ptr();
		let maxlen = EnclaveAttestationOCallApiImpl::RET_QUOTE_BUF_LEN as u32;
		let p_quote_len = &mut quote_len as *mut u32;

		let result = unsafe {
			ffi::ocall_get_quote(
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

		let consolidated_status = consolidate_sgx_status(result, rt);

		let quote_vec: Vec<u8> = Vec::from(&return_quote_buf[..quote_len as usize]);

		(consolidated_status, qe_report, quote_vec)
	}
}

fn consolidate_sgx_status(status_1: sgx_status_t, status_2: sgx_status_t) -> sgx_status_t {
	if status_1 != sgx_status_t::SGX_SUCCESS {
		return status_1
	}

	if status_2 != sgx_status_t::SGX_SUCCESS {
		return status_2
	}

	sgx_status_t::SGX_SUCCESS
}
