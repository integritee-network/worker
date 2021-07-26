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

/// trait for handling blocks on the side chain
pub trait SideChain: Send + Sync + 'static {
	fn produce_blocks(&self, blocks: Vec<u8>, nonce: u32) -> EnclaveResult<()>;
}

impl SideChain for Enclave {
	fn produce_blocks(&self, blocks: Vec<u8>, nonce: u32) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe {
			ffi::produce_blocks(self.eid, &mut retval, blocks.as_ptr(), blocks.len(), &nonce)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}
}
