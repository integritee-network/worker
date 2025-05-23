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
use ita_stf::ParentchainHeader;
use itc_parentchain::primitives::ParentchainId;
use itp_ocall_api::{EnclaveOnChainOCallApi, Result};
use itp_storage::{verify_storage_entries, Error::StorageValueUnavailable};
use itp_types::{
	storage::{StorageEntry, StorageEntryVerified},
	WorkerRequest, WorkerResponse, H256,
};
use itp_utils::hex::hex_encode;
use log::*;
use sgx_types::*;
use sp_runtime::{traits::Header, OpaqueExtrinsic};
use std::vec::Vec;

impl EnclaveOnChainOCallApi for OcallApi {
	fn send_to_parentchain(
		&self,
		extrinsics: Vec<OpaqueExtrinsic>,
		parentchain_id: &ParentchainId,
		await_each_inclusion: bool,
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
				await_each_inclusion.into(),
			)
		};

		ensure!(rt == sgx_status_t::SGX_SUCCESS, rt);
		ensure!(res == sgx_status_t::SGX_SUCCESS, res);

		Ok(())
	}

	fn worker_request<H: Header<Hash = H256>, V: Encode + Decode>(
		&self,
		req: Vec<WorkerRequest>,
		parentchain_id: &ParentchainId,
	) -> SgxResult<Vec<WorkerResponse<H, V>>> {
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

		let decoded_response: Vec<WorkerResponse<H, V>> = Decode::decode(&mut resp.as_slice())
			.map_err(|e| {
				error!("Failed to decode WorkerResponse: {}. Raw: {}", e, hex_encode(&resp));
				sgx_status_t::SGX_ERROR_UNEXPECTED
			})?;

		Ok(decoded_response)
	}

	/// get verified L1 storage entiry
	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
		parentchain_id: &ParentchainId,
	) -> Result<V> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		let opaque_value_verified = self
			.get_multiple_opaque_storages_verified(vec![storage_hash], header, parentchain_id)?
			.into_iter()
			.next()
			.and_then(|sv| sv.value)
			.ok_or_else(|| itp_ocall_api::Error::Storage(StorageValueUnavailable))?;
		Decode::decode(&mut opaque_value_verified.as_slice()).map_err(itp_ocall_api::Error::Codec)
	}

	/// this returns opaque/encoded values as we can't assume all values are of same type
	fn get_multiple_opaque_storages_verified<H: Header<Hash = H256>>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
		parentchain_id: &ParentchainId,
	) -> Result<Vec<StorageEntryVerified<Vec<u8>>>> {
		let requests = storage_hashes
			.into_iter()
			.map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
			.collect();

		let storage_entries = self
			.worker_request::<ParentchainHeader, Vec<u8>>(requests, parentchain_id)
			.map(|responses| {
				responses
					.into_iter()
					.map(|response| response.into())
					.collect::<Vec<StorageEntry<_>>>()
			})?;
		let verified_entries = verify_storage_entries(storage_entries, header).map_err(|e| {
			warn!("Failed to verify storage entry proofs: {:?}", e);
			e
		})?;

		Ok(verified_entries)
	}
}
