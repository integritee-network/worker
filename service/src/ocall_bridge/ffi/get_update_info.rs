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
use sgx_types::{sgx_platform_info_t, sgx_status_t, sgx_update_info_bit_t};
use std::sync::Arc;

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
	p_platform_blob: *const sgx_platform_info_t,
	enclave_trusted: i32,
	p_update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
	get_update_info(
		p_platform_blob,
		enclave_trusted,
		p_update_info,
		Bridge::get_ra_api(), // inject the RA API (global state)
	)
}

fn get_update_info(
	p_platform_blob: *const sgx_platform_info_t,
	enclave_trusted: i32,
	p_update_info: *mut sgx_update_info_bit_t,
	ra_api: Arc<dyn RemoteAttestationBridge>,
) -> sgx_status_t {
	debug!("    Entering ocall_get_update_info");

	let platform_blob = unsafe { *p_platform_blob };

	let update_info_result = match ra_api.get_update_info(platform_blob, enclave_trusted) {
		Ok(r) => r,
		Err(e) => {
			error!("[-]  Failed to get update info: {:?}", e);
			return e.into()
		},
	};

	unsafe {
		*p_update_info = update_info_result;
	}

	sgx_status_t::SGX_SUCCESS
}
