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
use itc_parentchain::primitives::ParentchainId;
use itp_ocall_api::{EnclaveOnChainOCallApi, Result};
use itp_storage::{verify_storage_entries, Error as StorageError};
use itp_types::{storage::StorageEntryVerified, WorkerRequest, WorkerResponse, H256};
use log::*;
use sgx_types::*;
use sp_runtime::{traits::Header, OpaqueExtrinsic};
use std::vec::Vec;

impl EnclaveOnChainOCallApi for OcallApi {
	fn send_to_parentchain(
		&self,
		extrinsics: Vec<OpaqueExtrinsic>,
		parentchain_id: &ParentchainId,
	) -> SgxResult<()> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let extrinsics_encoded = extrinsics.encode();
		let parentchain_id_encoded = parentchain_id.encode();

		let res = unsafe {
			ffi::ocall_send_to_parentchain(
				&mut rt as *mut sgx_status_t,
				extrinsics_encoded.as_ptr(),
				extrinsics_encoded.len() as u32,
				parentchain_id_encoded.as_ptr(),
				parentchain_id_encoded.len() as u32,
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(())
	}

	fn worker_request<V: Encode + Decode>(
		&self,
		req: Vec<WorkerRequest>,
		parentchain_id: &ParentchainId,
	) -> SgxResult<Vec<WorkerResponse<V>>> {
		let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
		let mut resp: Vec<u8> = vec![0; 4196 * 4];
		let request_encoded = req.encode();
		let parentchain_id_encoded = parentchain_id.encode();

		let res = unsafe {
			ffi::ocall_worker_request(
				&mut rt as *mut sgx_status_t,
				request_encoded.as_ptr(),
				request_encoded.len() as u32,
				parentchain_id_encoded.as_ptr(),
				parentchain_id_encoded.len() as u32,
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

	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
		parentchain_id: &ParentchainId,
	) -> Result<StorageEntryVerified<V>> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		Ok(self
			.get_multiple_storages_verified(vec![storage_hash], header, parentchain_id)?
			.into_iter()
			.next()
			.ok_or(StorageError::StorageValueUnavailable)?)
	}

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
		parentchain_id: &ParentchainId,
	) -> Result<Vec<StorageEntryVerified<V>>> {
		let requests = storage_hashes
			.into_iter()
			.map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
			.collect();

		let storage_entries = self
			.worker_request::<Vec<u8>>(requests, parentchain_id)
			.map(|storages| verify_storage_entries(storages, header))??;

		Ok(storage_entries)
	}
}
