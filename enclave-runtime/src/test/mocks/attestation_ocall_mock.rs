/*
	CCopyright 2021 Integritee AG and Supercomputing Systems AG
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

use itp_ocall_api::EnclaveAttestationOCallApi;
use sgx_types::*;
use std::{
	fmt::{Debug, Formatter, Result as FormatResult},
	vec::Vec,
};

#[derive(Clone)]
pub struct AttestationOCallMock {
	mr_enclave: sgx_measurement_t,
}

impl AttestationOCallMock {
	pub fn new() -> Self {
		Default::default()
	}

	pub fn create_with_mr_enclave(mr_enclave: sgx_measurement_t) -> Self {
		AttestationOCallMock { mr_enclave }
	}
}

impl EnclaveAttestationOCallApi for AttestationOCallMock {
	fn sgx_init_quote(&self) -> SgxResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
		unreachable!()
	}

	fn get_ias_socket(&self) -> SgxResult<i32> {
		unreachable!()
	}

	fn get_quote(
		&self,
		_sig_rl: Vec<u8>,
		_report: sgx_report_t,
		_sign_type: sgx_quote_sign_type_t,
		_spid: sgx_spid_t,
		_quote_nonce: sgx_quote_nonce_t,
	) -> SgxResult<(sgx_report_t, Vec<u8>)> {
		unreachable!()
	}

	fn get_dcap_quote(&self, _report: sgx_report_t, _quote_size: u32) -> SgxResult<Vec<u8>> {
		unreachable!()
	}

	fn get_qve_report_on_quote(
		&self,
		_quote: Vec<u8>,
		_current_time: i64,
		_quote_collateral: sgx_ql_qve_collateral_t,
		_qve_report_info: sgx_ql_qe_report_info_t,
		_supplemental_data_size: u32,
	) -> SgxResult<(u32, sgx_ql_qv_result_t, sgx_ql_qe_report_info_t, Vec<u8>)> {
		unreachable!()
	}

	fn get_update_info(
		&self,
		_platform_info: sgx_platform_info_t,
		_enclave_trusted: i32,
	) -> SgxResult<sgx_update_info_bit_t> {
		Ok(sgx_update_info_bit_t { csmeFwUpdate: 0, pswUpdate: 0, ucodeUpdate: 0 })
	}

	fn get_mrenclave_of_self(&self) -> SgxResult<sgx_measurement_t> {
		Ok(self.mr_enclave)
	}
}

impl Default for AttestationOCallMock {
	fn default() -> Self {
		AttestationOCallMock { mr_enclave: sgx_measurement_t { m: [1; SGX_HASH_SIZE] } }
	}
}

impl Debug for AttestationOCallMock {
	fn fmt(&self, f: &mut Formatter<'_>) -> FormatResult {
		f.debug_struct("AttestationOCallMock")
			.field("mr_enclave", &self.mr_enclave.m)
			.finish()
	}
}
