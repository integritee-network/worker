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

use crate::{error::Error, Enclave, EnclaveResult};
use frame_support::ensure;
use sgx_types::sgx_status_t;
use substratee_enclave_api_ffi as ffi;

pub trait DirectRequest: Send + Sync + 'static {
	// Todo: Vec<u8> shall be replaced by D: Decode, E: Encode but this is currently
	// not compatible with the direct_api_server...
	fn rpc(&self, request: Vec<u8>) -> EnclaveResult<Vec<u8>>;

	fn initialize_pool(&self) -> EnclaveResult<()>;
}

impl DirectRequest for Enclave {
	fn rpc(&self, request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let response_len = 8192;
		let mut response: Vec<u8> = vec![0u8; response_len as usize];

		let res = unsafe {
			ffi::call_rpc_methods(
				self.eid,
				&mut retval,
				request.as_ptr(),
				request.len() as u32,
				response.as_mut_ptr(),
				response_len,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(response)
	}

	fn initialize_pool(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe { ffi::initialize_pool(self.eid, &mut retval) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}
}
