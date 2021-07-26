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

use sgx_types::{
	sgx_epid_group_id_t, sgx_quote_nonce_t, sgx_quote_sign_type_t, sgx_report_t, sgx_spid_t,
	sgx_status_t, sgx_target_info_t,
};
use std::vec::Vec;

/// Trait for the enclave to make ocalls (calls out of the enclave into untrusted code)
pub trait EnclaveAttestationOCallApi {
	fn ocall_sgx_init_quote(&self) -> (sgx_status_t, sgx_target_info_t, sgx_epid_group_id_t);

	fn ocall_get_ias_socket(&self) -> (sgx_status_t, i32);

	fn ocall_get_quote(
		&self,
		sig_rl: Vec<u8>,
		report: sgx_report_t,
		sign_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> (sgx_status_t, sgx_report_t, Vec<u8>);
}
