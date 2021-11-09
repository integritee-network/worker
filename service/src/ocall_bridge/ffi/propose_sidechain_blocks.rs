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

use crate::ocall_bridge::bridge_api::{Bridge, SidechainBridge};
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_propose_sidechain_blocks(
	signed_blocks_ptr: *const u8,
	signed_blocks_size: u32,
) -> sgx_status_t {
	propose_sidechain_blocks(signed_blocks_ptr, signed_blocks_size, Bridge::get_sidechain_api())
}

fn propose_sidechain_blocks(
	signed_blocks_ptr: *const u8,
	signed_blocks_size: u32,
	sidechain_api: Arc<dyn SidechainBridge>,
) -> sgx_status_t {
	let signed_blocks_vec: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(signed_blocks_ptr, signed_blocks_size as usize)) };

	match sidechain_api.propose_sidechain_blocks(signed_blocks_vec) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("send sidechain blocks failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
