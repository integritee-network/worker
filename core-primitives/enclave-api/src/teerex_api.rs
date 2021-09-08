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

use crate::{error::Error, Enclave, EnclaveResult};
use codec::Encode;
use frame_support::{ensure, sp_runtime::app_crypto::sp_core::H256};
use itp_enclave_api_ffi as ffi;
use sgx_types::*;

pub trait TeerexApi: Send + Sync + 'static {
	/// Register enclave xt with an empty attestation report.
	fn mock_register_xt(
		&self,
		genesis_hash: H256,
		nonce: u32,
		w_url: &str,
	) -> EnclaveResult<Vec<u8>>;
}

impl TeerexApi for Enclave {
	fn mock_register_xt(
		&self,
		genesis_hash: H256,
		nonce: u32,
		w_url: &str,
	) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let response_len = 8192;
		let mut response: Vec<u8> = vec![0u8; response_len as usize];

		let url = w_url.encode();
		let gen = genesis_hash.as_bytes().to_vec();

		let res = unsafe {
			ffi::mock_register_enclave_xt(
				self.eid,
				&mut retval,
				gen.as_ptr(),
				gen.len() as u32,
				&nonce,
				url.as_ptr(),
				url.len() as u32,
				response.as_mut_ptr(),
				response_len,
			)
		};

		ensure!(res == sgx_status_t::SGX_SUCCESS, Error::Sgx(res));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(response)
	}
}
