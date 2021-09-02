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

use crate::ocall_bridge::bridge_api::{Bridge, Cid, IpfsBridge};
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

/// C-API exposed for o-call from enclave
#[no_mangle]
pub unsafe extern "C" fn ocall_write_ipfs(
	enc_state: *const u8,
	enc_state_size: u32,
	cid: *mut u8,
	cid_size: u32,
) -> sgx_status_t {
	write_ipfs(enc_state, enc_state_size, cid, cid_size, Bridge::get_ipfs_api())
}

/// C-API exposed for o-call from enclave
#[no_mangle]
pub unsafe extern "C" fn ocall_read_ipfs(cid: *const u8, cid_size: u32) -> sgx_status_t {
	read_ipfs(cid, cid_size, Bridge::get_ipfs_api())
}

fn write_ipfs(
	enc_state: *const u8,
	enc_state_size: u32,
	cid: *mut u8,
	cid_size: u32,
	ipfs_api: Arc<dyn IpfsBridge>,
) -> sgx_status_t {
	let state = unsafe { slice::from_raw_parts(enc_state, enc_state_size as usize) };
	let cid = unsafe { slice::from_raw_parts_mut(cid, cid_size as usize) };

	return match ipfs_api.write_to_ipfs(state) {
		Ok(r) => {
			cid.clone_from_slice(&r);
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => {
			error!("OCall to write_ipfs failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}

fn read_ipfs(cid: *const u8, cid_size: u32, ipfs_api: Arc<dyn IpfsBridge>) -> sgx_status_t {
	let _cid = unsafe { slice::from_raw_parts(cid, cid_size as usize) };

	let mut cid: Cid = [0; 46];
	cid.clone_from_slice(_cid);

	match ipfs_api.read_from_ipfs(cid) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("OCall to read_ipfs failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
