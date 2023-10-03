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

use crate::ocall_bridge::bridge_api::{Bridge, WorkerOnChainBridge};
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc, vec::Vec};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_worker_request(
	request: *const u8,
	req_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
	response: *mut u8,
	resp_size: u32,
) -> sgx_status_t {
	worker_request(
		request,
		req_size,
		parentchain_id,
		parentchain_id_size,
		response,
		resp_size,
		Bridge::get_oc_api(),
	)
}

fn worker_request(
	request: *const u8,
	req_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
	response: *mut u8,
	resp_size: u32,
	oc_api: Arc<dyn WorkerOnChainBridge>,
) -> sgx_status_t {
	let request_vec: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(request, req_size as usize)) };

	let parentchain_id: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(parentchain_id, parentchain_id_size as usize)) };

	match oc_api.worker_request(request_vec, parentchain_id) {
		Ok(r) => {
			let resp_slice = unsafe { slice::from_raw_parts_mut(response, resp_size as usize) };
			if let Err(e) = write_slice_and_whitespace_pad(resp_slice, r) {
				error!("Failed to transfer worker request response to o-call buffer: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			}
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => {
			error!("Worker request failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
