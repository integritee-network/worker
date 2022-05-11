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

use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::{
	EnclaveAttestationOCallApi, EnclaveMetricsOCallApi, EnclaveOnChainOCallApi,
	EnclaveSidechainOCallApi,
};
use itp_storage::StorageEntryVerified;
use itp_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use itp_types::{BlockHash, Enclave, ShardIdentifier, WorkerRequest, WorkerResponse};
use sgx_types::{
	sgx_epid_group_id_t, sgx_measurement_t, sgx_platform_info_t, sgx_quote_nonce_t,
	sgx_quote_sign_type_t, sgx_report_t, sgx_spid_t, sgx_target_info_t, sgx_update_info_bit_t,
	SgxResult, SGX_HASH_SIZE,
};
use sp_core::H256;
use sp_runtime::{traits::Header as HeaderT, AccountId32, OpaqueExtrinsic};
use sp_std::prelude::*;
use std::collections::HashMap;

#[derive(Default, Clone, Debug)]
pub struct OnchainMock {
	inner: HashMap<Vec<u8>, Vec<u8>>,
	mr_enclave: [u8; SGX_HASH_SIZE],
}

impl OnchainMock {
	pub fn with_storage_entries<V: Encode>(mut self, entries: Vec<(Vec<u8>, V)>) -> Self {
		for (k, v) in entries.into_iter() {
			self.inner.insert(k, v.encode());
		}
		self
	}

	pub fn with_validateer_set(mut self, set: Option<Vec<Enclave>>) -> Self {
		let set = set.unwrap_or_else(validateer_set);
		self.inner.insert(TeeRexStorage::enclave_count(), (set.len() as u64).encode());
		self.with_storage_entries(into_key_value_storage(set))
	}

	pub fn with_mr_enclave(mut self, mr_enclave: [u8; SGX_HASH_SIZE]) -> Self {
		self.mr_enclave = mr_enclave;
		self
	}

	pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
		self.inner.insert(key, value);
	}

	pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
		self.inner.get(key)
	}
}

impl EnclaveAttestationOCallApi for OnchainMock {
	fn sgx_init_quote(&self) -> SgxResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
		todo!()
	}

	fn get_ias_socket(&self) -> SgxResult<i32> {
		Ok(42)
	}

	fn get_quote(
		&self,
		_sig_rl: Vec<u8>,
		_report: sgx_report_t,
		_sign_type: sgx_quote_sign_type_t,
		_spid: sgx_spid_t,
		_quote_nonce: sgx_quote_nonce_t,
	) -> SgxResult<(sgx_report_t, Vec<u8>)> {
		todo!()
	}

	fn get_update_info(
		&self,
		_platform_info: sgx_platform_info_t,
		_enclave_trusted: i32,
	) -> SgxResult<sgx_update_info_bit_t> {
		todo!()
	}

	fn get_mrenclave_of_self(&self) -> SgxResult<sgx_measurement_t> {
		Ok(sgx_measurement_t { m: self.mr_enclave })
	}
}

impl EnclaveSidechainOCallApi for OnchainMock {
	fn propose_sidechain_blocks<SignedSidechainBlock: Encode>(
		&self,
		_signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()> {
		Ok(())
	}

	fn store_sidechain_blocks<SignedSidechainBlock: Encode>(
		&self,
		_signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()> {
		Ok(())
	}

	fn fetch_sidechain_blocks_from_peer<SignedSidechainBlock: Decode>(
		&self,
		_last_known_block_hash: BlockHash,
		_shard_identifier: ShardIdentifier,
	) -> SgxResult<Vec<SignedSidechainBlock>> {
		Ok(Vec::new())
	}
}

impl EnclaveMetricsOCallApi for OnchainMock {
	fn update_metric<Metric: Encode>(&self, _metric: Metric) -> SgxResult<()> {
		Ok(())
	}
}

impl EnclaveOnChainOCallApi for OnchainMock {
	fn send_to_parentchain(&self, _extrinsics: Vec<OpaqueExtrinsic>) -> SgxResult<()> {
		Ok(())
	}

	fn worker_request<V: Encode + Decode>(
		&self,
		_req: Vec<WorkerRequest>,
	) -> SgxResult<Vec<WorkerResponse<V>>> {
		Ok(Vec::new())
	}

	fn get_storage_verified<H: HeaderT<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		_header: &H,
	) -> Result<StorageEntryVerified<V>, itp_ocall_api::Error> {
		let value = self
			.get(&storage_hash)
			.map(|val| Decode::decode(&mut val.as_slice()))
			.transpose()
			.map_err(itp_ocall_api::Error::Codec)?;

		Ok(StorageEntryVerified::new(storage_hash, value))
	}

	fn get_multiple_storages_verified<H: HeaderT<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		_header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>, itp_ocall_api::Error> {
		let mut entries = Vec::with_capacity(storage_hashes.len());
		for hash in storage_hashes.into_iter() {
			let value = self
				.get(&hash)
				.map(|val| Decode::decode(&mut val.as_slice()))
				.transpose()
				.map_err(itp_ocall_api::Error::Codec)?;

			entries.push(StorageEntryVerified::new(hash, value))
		}
		Ok(entries)
	}
}

pub fn validateer_set() -> Vec<Enclave> {
	let default_enclave = Enclave::new(
		AccountId32::from([0; 32]),
		Default::default(),
		Default::default(),
		Default::default(),
	);
	vec![default_enclave.clone(), default_enclave.clone(), default_enclave.clone(), default_enclave]
}

fn into_key_value_storage(validateers: Vec<Enclave>) -> Vec<(Vec<u8>, Enclave)> {
	validateers
		.into_iter()
		.enumerate()
		.map(|(i, e)| (TeeRexStorage::enclave(i as u64 + 1), e))
		.collect()
}
