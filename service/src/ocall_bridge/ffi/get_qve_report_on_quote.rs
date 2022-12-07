/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
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

use crate::ocall_bridge::bridge_api::{Bridge, RemoteAttestationBridge};
use log::*;
use sgx_types::*;
use std::{slice, sync::Arc};

#[no_mangle]
pub unsafe extern "C" fn ocall_get_qve_report_on_quote(
	p_quote: *const u8,
	quote_len: u32,
	current_time: i64,
	p_quote_collateral: *const sgx_ql_qve_collateral_t,
	p_collateral_expiration_status: *mut u32,
	p_quote_verification_result: *mut sgx_ql_qv_result_t,
	p_qve_report_info: *mut sgx_ql_qe_report_info_t,
	p_supplemental_data: *mut u8,
	supplemental_data_size: u32,
) -> sgx_status_t {
	get_qve_report_on_quote(
		p_quote,
		quote_len,
		current_time,
		p_quote_collateral,
		p_collateral_expiration_status,
		p_quote_verification_result,
		p_qve_report_info,
		p_supplemental_data,
		supplemental_data_size,
		Bridge::get_ra_api(), // inject the RA API (global state)
	)
}

#[allow(clippy::too_many_arguments)]
fn get_qve_report_on_quote(
	p_quote: *const u8,
	quote_len: u32,
	current_time: i64,
	p_quote_collateral: *const sgx_ql_qve_collateral_t,
	p_collateral_expiration_status: *mut u32,
	p_quote_verification_result: *mut sgx_ql_qv_result_t,
	p_qve_report_info: *mut sgx_ql_qe_report_info_t,
	p_supplemental_data: *mut u8,
	supplemental_data_size: u32,
	ra_api: Arc<dyn RemoteAttestationBridge>,
) -> sgx_status_t {
	debug!("Entering ocall_get_qve_report_on_quote");
	if p_quote.is_null()
		|| quote_len == 0
		|| p_quote_collateral.is_null()
		|| p_collateral_expiration_status.is_null()
		|| p_quote_verification_result.is_null()
		|| p_qve_report_info.is_null()
		|| p_supplemental_data.is_null()
		|| supplemental_data_size == 0
	{
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let quote: Vec<u8> = unsafe { slice::from_raw_parts(p_quote, quote_len as usize).to_vec() };
	let quote_collateral = unsafe { &*p_quote_collateral };
	let qve_report_info = unsafe { *p_qve_report_info };

	let qve_report = match ra_api.get_qve_report_on_quote(
		quote,
		current_time,
		quote_collateral,
		qve_report_info,
		supplemental_data_size,
	) {
		Ok(return_values) => return_values,
		Err(e) => {
			error!("Failed to get quote: {:?}", e);
			return e.into()
		},
	};

	let supplemental_data_slice =
		unsafe { slice::from_raw_parts_mut(p_supplemental_data, supplemental_data_size as usize) };
	supplemental_data_slice.clone_from_slice(qve_report.supplemental_data.as_slice());

	unsafe {
		*p_collateral_expiration_status = qve_report.collateral_expiration_status;
		*p_quote_verification_result = qve_report.quote_verification_result;
		*p_qve_report_info = qve_report.qve_report_info_return_value;
	};

	sgx_status_t::SGX_SUCCESS
}
