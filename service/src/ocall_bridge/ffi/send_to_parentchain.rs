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
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc, vec::Vec};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_send_to_parentchain(
	extrinsics_encoded: *const u8,
	extrinsics_encoded_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> sgx_status_t {
	send_to_parentchain(
		extrinsics_encoded,
		extrinsics_encoded_size,
		parentchain_id,
		parentchain_id_size,
		Bridge::get_oc_api(),
	)
}

fn send_to_parentchain(
	extrinsics_encoded: *const u8,
	extrinsics_encoded_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
	oc_api: Arc<dyn WorkerOnChainBridge>,
) -> sgx_status_t {
	let extrinsics_encoded_vec: Vec<u8> = unsafe {
		Vec::from(slice::from_raw_parts(extrinsics_encoded, extrinsics_encoded_size as usize))
	};

	let parentchain_id: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(parentchain_id, parentchain_id_size as usize)) };

	match oc_api.send_to_parentchain(extrinsics_encoded_vec, parentchain_id) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("send extrinsics_encoded failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
