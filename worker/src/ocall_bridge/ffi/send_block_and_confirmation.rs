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

use crate::ocall_bridge::bridge_api::{Bridge, WorkerOnChainBridge};
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc, vec::Vec};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_send_block_and_confirmation(
	confirmations: *const u8,
	confirmations_size: u32,
	signed_blocks_ptr: *const u8,
	signed_blocks_size: u32,
) -> sgx_status_t {
	send_block_and_confirmation(
		confirmations,
		confirmations_size,
		signed_blocks_ptr,
		signed_blocks_size,
		Bridge::get_oc_api(),
	)
}

fn send_block_and_confirmation(
	confirmations: *const u8,
	confirmations_size: u32,
	signed_blocks_ptr: *const u8,
	signed_blocks_size: u32,
	oc_api: Arc<dyn WorkerOnChainBridge>,
) -> sgx_status_t {
	let confirmations_vec: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(confirmations, confirmations_size as usize)) };

	let signed_blocks_vec: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(signed_blocks_ptr, signed_blocks_size as usize)) };

	match oc_api.send_block_and_confirmation(confirmations_vec, signed_blocks_vec) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("send block and confirmation failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
