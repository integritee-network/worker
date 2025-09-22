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
use itp_ocall_api::EnclaveIpfsOCallApi;
use itp_types::IpfsCid;
use log::warn;
use sgx_types::{sgx_status_t, SgxResult};

impl EnclaveIpfsOCallApi for OcallApi {
	fn write_ipfs(&self, content: &[u8]) -> SgxResult<IpfsCid> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut cid_buf = [0u8; 46]; //max expected length for an encoded cid
		let res = unsafe {
			ffi::ocall_write_ipfs(
				&mut rt as *mut sgx_status_t,
				content.as_ptr(),
				content.len() as u32,
				cid_buf.as_mut_ptr(),
				cid_buf.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		let cid = IpfsCid::default();
		// TODO: actually decode the returned cid
		// cid.decode(&mut cid_buf.as_slice())
		//	.map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
		Ok(cid)
	}

	fn read_ipfs(&self, cid: &IpfsCid) -> SgxResult<Vec<u8>> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let cid_buf = cid.encode();
		let res = unsafe {
			ffi::ocall_read_ipfs(
				&mut rt as *mut sgx_status_t,
				cid_buf.as_ptr(),
				cid_buf.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		warn!("IPFS read not implemented, returning empty vec");
		Ok(vec![])
	}
}
