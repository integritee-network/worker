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

use crate::ocall_bridge::bridge_api::{Bridge, IpfsBridge};
use codec::{Decode, Encode};
use itp_ipfs_cid::IpfsCid;
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

/// C-API exposed for o-call from enclave
#[no_mangle]
pub unsafe extern "C" fn ocall_write_ipfs(
	content_ptr: *const u8,
	content_size: u32,
) -> sgx_status_t {
	let content: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(content_ptr, content_size as usize)) };
	let _ = Bridge::get_ipfs_api().write_to_ipfs(content);
	sgx_status_t::SGX_SUCCESS
}
