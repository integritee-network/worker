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
use sgx_types::{sgx_epid_group_id_t, sgx_status_t, sgx_target_info_t};
use std::sync::Arc;

#[no_mangle]
pub unsafe extern "C" fn ocall_sgx_init_quote(
	ret_ti: *mut sgx_target_info_t,
	ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
	sgx_init_quote(ret_ti, ret_gid, Bridge::get_ra_api()) // inject the RA API (global state)
}

fn sgx_init_quote(
	ret_ti: *mut sgx_target_info_t,
	ret_gid: *mut sgx_epid_group_id_t,
	ra_api: Arc<dyn RemoteAttestationBridge>,
) -> sgx_status_t {
	debug!("    Entering ocall_sgx_init_quote");
	let init_result = match ra_api.init_quote() {
		Ok(r) => r,
		Err(e) => {
			error!("[-]  Failed to init quote: {:?}", e);
			return e.into()
		},
	};

	unsafe {
		*ret_ti = init_result.0;
		*ret_gid = init_result.1;
	}

	sgx_status_t::SGX_SUCCESS
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::ocall_bridge::bridge_api::MockRemoteAttestationBridge;
	use std::sync::Arc;

	#[test]
	fn init_quote_sets_results() {
		let mut ra_ocall_api_mock = MockRemoteAttestationBridge::new();
		ra_ocall_api_mock
			.expect_init_quote()
			.times(1)
			.returning(|| Ok((dummy_target_info(), [8u8; 4])));

		let mut ti: sgx_target_info_t = sgx_target_info_t::default();
		let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

		let ret_status = sgx_init_quote(
			&mut ti as *mut sgx_target_info_t,
			&mut eg as *mut sgx_epid_group_id_t,
			Arc::new(ra_ocall_api_mock),
		);

		assert_eq!(ret_status, sgx_status_t::SGX_SUCCESS);
		assert_eq!(eg, [8u8; 4]);
	}

	fn dummy_target_info() -> sgx_target_info_t {
		sgx_target_info_t::default()
	}
}
