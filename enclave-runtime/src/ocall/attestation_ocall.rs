/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use crate::ocall::{ffi, OcallApi};
use frame_support::ensure;
use itp_ocall_api::EnclaveAttestationOCallApi;
use log::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use std::{ptr, vec::Vec};

const RET_QUOTE_BUF_LEN: usize = 2048;

impl EnclaveAttestationOCallApi for OcallApi {
	fn sgx_init_quote(&self) -> SgxResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
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

		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok((ti, eg))
	}

	fn get_ias_socket(&self) -> SgxResult<i32> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut ias_sock: i32 = 0;

		let res = unsafe {
			ffi::ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok(ias_sock)
	}

	fn get_quote(
		&self,
		sig_rl: Vec<u8>,
		report: sgx_report_t,
		sign_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> SgxResult<(sgx_report_t, Vec<u8>)> {
		let mut qe_report = sgx_report_t::default();
		let mut return_quote_buf = [0u8; RET_QUOTE_BUF_LEN];
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
		let maxlen = RET_QUOTE_BUF_LEN as u32;
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

		ensure!(result == sgx_status_t::SGX_SUCCESS, result);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		let quote_vec: Vec<u8> = Vec::from(&return_quote_buf[..quote_len as usize]);

		Ok((qe_report, quote_vec))
	}

	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> SgxResult<Vec<u8>> {
		let mut return_quote_buf = vec![0u8; quote_size as usize];
		let p_quote = return_quote_buf.as_mut_ptr();
		let p_report = &report as *const sgx_report_t;
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let result = unsafe {
			ffi::ocall_get_dcap_quote(&mut rt as *mut sgx_status_t, p_report, p_quote, quote_size)
		};
		ensure!(result == sgx_status_t::SGX_SUCCESS, result);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		let quote_vec: Vec<u8> = Vec::from(&return_quote_buf[..quote_size as usize]);
		Ok(quote_vec)
	}

	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> SgxResult<(u32, sgx_ql_qv_result_t, sgx_ql_qe_report_info_t, Vec<u8>)> {
		let mut supplemental_data = vec![0u8; supplemental_data_size as usize];
		let mut qve_report_info_return_value: sgx_ql_qe_report_info_t = qve_report_info;
		let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
		let mut collateral_expiration_status = 1u32;
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let result = unsafe {
			ffi::ocall_get_qve_report_on_quote(
				&mut rt as *mut sgx_status_t,
				quote.as_ptr(),
				quote.len() as u32,
				current_time,
				&quote_collateral as *const sgx_ql_qve_collateral_t,
				&mut collateral_expiration_status as *mut u32,
				&mut quote_verification_result as *mut sgx_ql_qv_result_t,
				&mut qve_report_info_return_value as *mut sgx_ql_qe_report_info_t,
				supplemental_data.as_mut_ptr(),
				supplemental_data_size,
			)
		};
		ensure!(result == sgx_status_t::SGX_SUCCESS, result);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok((
			collateral_expiration_status,
			quote_verification_result,
			qve_report_info_return_value,
			supplemental_data.to_vec(),
		))
	}

	fn get_update_info(
		&self,
		platform_info: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> SgxResult<sgx_update_info_bit_t> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut update_info = sgx_update_info_bit_t::default();

		let result = unsafe {
			ffi::ocall_get_update_info(
				&mut rt as *mut sgx_status_t,
				&platform_info as *const sgx_platform_info_t,
				enclave_trusted,
				&mut update_info as *mut sgx_update_info_bit_t,
			)
		};

		// debug logging
		if rt != sgx_status_t::SGX_SUCCESS {
			warn!("ocall_get_update_info unsuccessful. rt={:?}", rt);
			// Curly braces to copy `unaligned_references` of packed fields into properly aligned temporary:
			// https://github.com/rust-lang/rust/issues/82523
			debug!("update_info.pswUpdate: {}", { update_info.pswUpdate });
			debug!("update_info.csmeFwUpdate: {}", { update_info.csmeFwUpdate });
			debug!("update_info.ucodeUpdate: {}", { update_info.ucodeUpdate });
		}

		ensure!(result == sgx_status_t::SGX_SUCCESS, result);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok(update_info)
	}

	fn get_mrenclave_of_self(&self) -> SgxResult<sgx_measurement_t> {
		Ok(self.get_report_of_self()?.mr_enclave)
	}
}

trait GetSgxReport {
	fn get_report_of_self(&self) -> SgxResult<sgx_report_body_t>;
}

impl<T: EnclaveAttestationOCallApi> GetSgxReport for T {
	fn get_report_of_self(&self) -> SgxResult<sgx_report_body_t> {
		// (1) get ti + eg
		let init_quote_result = self.sgx_init_quote()?;

		let target_info = init_quote_result.0;
		let report_data: sgx_report_data_t = sgx_report_data_t::default();

		let rep = match rsgx_create_report(&target_info, &report_data) {
			Ok(r) => {
				debug!(
					"    [Enclave] Report creation successful. mr_signer.m = {:?}",
					r.body.mr_signer.m
				);
				r
			},
			Err(e) => {
				error!("    [Enclave] Report creation failed. {:?}", e);
				return Err(e)
			},
		};
		Ok(rep.body)
	}
}
