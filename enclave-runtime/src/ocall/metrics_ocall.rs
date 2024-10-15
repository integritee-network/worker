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
use codec::Encode;
use frame_support::ensure;
use itp_ocall_api::EnclaveMetricsOCallApi;
use sgx_types::{sgx_status_t, SgxResult};
use std::vec::Vec;

impl EnclaveMetricsOCallApi for OcallApi {
	fn update_metrics<Metric: Encode>(&self, metrics: Vec<Metric>) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let metrics_encoded = metrics.encode();

		let res = unsafe {
			ffi::ocall_update_metrics(
				&mut rt as *mut sgx_status_t,
				metrics_encoded.as_ptr(),
				metrics_encoded.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(())
	}
}
