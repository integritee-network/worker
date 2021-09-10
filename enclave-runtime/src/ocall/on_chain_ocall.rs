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
use codec::{Decode, Encode};
use frame_support::ensure;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_types::{block::SignedBlock as SignedSidechainBlock, WorkerRequest, WorkerResponse};
use log::*;
use sgx_types::*;
use sp_runtime::OpaqueExtrinsic;
use std::vec::Vec;

impl EnclaveOnChainOCallApi for OcallApi {
	fn send_block_and_confirmation(
		&self,
		confirmations: Vec<OpaqueExtrinsic>,
		signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let confirmations_encoded = confirmations.encode();
		let signed_blocks_encoded = signed_blocks.encode();

		let res = unsafe {
			ffi::ocall_send_block_and_confirmation(
				&mut rt as *mut sgx_status_t,
				confirmations_encoded.as_ptr(),
				confirmations_encoded.len() as u32,
				signed_blocks_encoded.as_ptr(),
				signed_blocks_encoded.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(())
	}

	fn worker_request<V: Encode + Decode>(
		&self,
		req: Vec<WorkerRequest>,
	) -> SgxResult<Vec<WorkerResponse<V>>> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut resp: Vec<u8> = vec![0; 4196 * 4];
		let request_encoded = req.encode();

		let res = unsafe {
			ffi::ocall_worker_request(
				&mut rt as *mut sgx_status_t,
				request_encoded.as_ptr(),
				request_encoded.len() as u32,
				resp.as_mut_ptr(),
				resp.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		let decoded_response: Vec<WorkerResponse<V>> = Decode::decode(&mut resp.as_slice())
			.map_err(|e| {
				error!("Failed to decode WorkerResponse: {}", e);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			})?;

		Ok(decoded_response)
	}
}
