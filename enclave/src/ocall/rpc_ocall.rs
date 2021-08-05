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

use crate::ocall::ffi;
use codec::Encode;
use frame_support::ensure;
use sgx_types::{sgx_status_t, SgxResult};
use std::vec::Vec;
use substratee_ocall_api::EnclaveRpcOCallApi;
use substratee_worker_primitives::TrustedOperationStatus;

#[derive(Clone, Debug, Default)]
pub struct EnclaveRpcOCall;

impl EnclaveRpcOCallApi for EnclaveRpcOCall {
	fn update_status_event<H: Encode>(
		&self,
		hash: H,
		status_update: TrustedOperationStatus,
	) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let hash_encoded = hash.encode();
		let status_update_encoded = status_update.encode();

		let res = unsafe {
			ffi::ocall_update_status_event(
				&mut rt as *mut sgx_status_t,
				hash_encoded.as_ptr(),
				hash_encoded.len() as u32,
				status_update_encoded.as_ptr(),
				status_update_encoded.len() as u32,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok(())
	}

	fn send_state<H: Encode>(&self, hash: H, value_opt: Option<Vec<u8>>) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

		let hash_encoded = hash.encode();
		let value_encoded = value_opt.encode();

		let res = unsafe {
			ffi::ocall_send_status(
				&mut rt as *mut sgx_status_t,
				hash_encoded.as_ptr(),
				hash_encoded.len() as u32,
				value_encoded.as_ptr(),
				value_encoded.len() as u32,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, res);
		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);

		Ok(())
	}
}
