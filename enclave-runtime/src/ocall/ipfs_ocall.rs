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
use crate::ocall::{ffi, OcallApi};
use alloc::vec::Vec;
use codec::Encode;
use frame_support::ensure;
use itp_ipfs_cid::IpfsCid;
use itp_ocall_api::EnclaveIpfsOCallApi;
use log::*;
use sgx_types::{sgx_status_t, SgxResult};

impl EnclaveIpfsOCallApi for OcallApi {
	fn write_ipfs(&self, content: Vec<u8>) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		trace!("calling OCallApi::write_ipfs with {} bytes", content.len());
		let payload = content.clone();
		let res = unsafe {
			ffi::ocall_write_ipfs(
				&mut rt as *mut sgx_status_t,
				payload.as_ptr(),
				payload.len() as u32,
			)
		};
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		trace!("completed OCallApi::write_ipfs");
		Ok(())
	}
}
