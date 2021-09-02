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
use frame_support::ensure;
use itp_ocall_api::{EnclaveIpfsOCallApi, IpfsCid};
use sgx_types::{sgx_status_t, SgxResult};

impl EnclaveIpfsOCallApi for OcallApi {
	fn write_ipfs(&self, encoded_state: &[u8]) -> SgxResult<IpfsCid> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut cid_buf = IpfsCid([0u8; 46]);

		let res = unsafe {
			ffi::ocall_write_ipfs(
				&mut rt as *mut sgx_status_t,
				encoded_state.as_ptr(),
				encoded_state.len() as u32,
				cid_buf.0.as_mut_ptr(),
				cid_buf.0.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(cid_buf)
	}

	fn read_ipfs(&self, cid: &IpfsCid) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let res = unsafe {
			ffi::ocall_read_ipfs(&mut rt as *mut sgx_status_t, cid.0.as_ptr(), cid.0.len() as u32)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(())
	}
}
