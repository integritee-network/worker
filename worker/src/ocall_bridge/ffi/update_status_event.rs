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

use crate::ocall_bridge::bridge_api::{Bridge, DirectInvocationBridge};
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

#[no_mangle]
pub unsafe extern "C" fn ocall_update_status_event(
	hash_encoded: *const u8,
	hash_size: u32,
	status_update_encoded: *const u8,
	status_size: u32,
) -> sgx_status_t {
	update_status_event(
		hash_encoded,
		hash_size,
		status_update_encoded,
		status_size,
		Bridge::get_direct_invocation_api(),
	)
}

fn update_status_event(
	hash_encoded: *const u8,
	hash_size: u32,
	status_update_encoded: *const u8,
	status_size: u32,
	direct_invocation: Arc<dyn DirectInvocationBridge>,
) -> sgx_status_t {
	let status_update_vec =
		unsafe { Vec::from(slice::from_raw_parts(status_update_encoded, status_size as usize)) };
	let hash_vec = unsafe { Vec::from(slice::from_raw_parts(hash_encoded, hash_size as usize)) };

	match direct_invocation.update_status_event(hash_vec, status_update_vec) {
		Ok(()) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("OCall to update_status_event failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
