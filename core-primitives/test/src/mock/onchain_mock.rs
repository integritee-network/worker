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
use itp_storage::Error::StorageValueUnavailable;
use itp_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use itp_types::{
	storage::StorageEntryVerified, BlockHash, Enclave, ShardIdentifier, WorkerRequest,
	WorkerResponse,
};
use sgx_types::*;
use sp_core::H256;
use sp_runtime::{traits::Header as HeaderTrait, AccountId32, OpaqueExtrinsic};
use sp_std::prelude::*;
use std::collections::HashMap;

#[derive(Default, Clone, Debug)]
pub struct OnchainMock {
	inner: HashMap<Vec<u8>, Vec<u8>>,
	mr_enclave: [u8; SGX_HASH_SIZE],
}

impl OnchainMock {
	pub fn with_storage_entries_at_header<Header: HeaderTrait<Hash = H256>, V: Encode>(
		mut self,
		header: &Header,
		entries: Vec<(Vec<u8>, V)>,
	) -> Self {
		for (key, value) in entries.into_iter() {
			self.insert_at_header(header, key, value.encode());
		}
		self
	}

	pub fn add_validateer_set<Header: HeaderTrait<Hash = H256>>(
		mut self,
		header: &Header,
		set: Option<Vec<Enclave>>,
	) -> Self {
		let set = set.unwrap_or_else(validateer_set);
		self.insert_at_header(header, TeeRexStorage::enclave_count(), (set.len() as u64).encode());
		self.with_storage_entries_at_header(header, into_key_value_storage(set))
	}

	pub fn with_mr_enclave(mut self, mr_enclave: [u8; SGX_HASH_SIZE]) -> Self {
		self.mr_enclave = mr_enclave;
		self
	}

	pub fn insert_at_header<Header: HeaderTrait<Hash = H256>>(
		&mut self,
		header: &Header,
		key: Vec<u8>,
		value: Vec<u8>,
	) {
		let key_with_header = (header, key).encode();
		self.inner.insert(key_with_header, value);
	}

	pub fn get_at_header<Header: HeaderTrait<Hash = H256>>(
		&self,
		header: &Header,
		key: &[u8],
	) -> Option<&Vec<u8>> {
		let key_with_header = (header, key).encode();
		self.inner.get(&key_with_header)
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

	fn get_dcap_quote(&self, _report: sgx_report_t, _quote_size: u32) -> SgxResult<Vec<u8>> {
		todo!()
	}

	fn get_qve_report_on_quote(
		&self,
		_quote: Vec<u8>,
		_current_time: i64,
		_quote_collateral: sgx_ql_qve_collateral_t,
		_qve_report_info: sgx_ql_qe_report_info_t,
		_supplemental_data_size: u32,
	) -> SgxResult<(u32, sgx_ql_qv_result_t, sgx_ql_qe_report_info_t, Vec<u8>)> {
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
		_last_imported_block_hash: BlockHash,
		_maybe_until_block_hash: Option<BlockHash>,
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

	fn get_storage_verified<Header: HeaderTrait<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &Header,
	) -> Result<StorageEntryVerified<V>, itp_ocall_api::Error> {
		self.get_multiple_storages_verified(vec![storage_hash], header)?
			.into_iter()
			.next()
			.ok_or_else(|| itp_ocall_api::Error::Storage(StorageValueUnavailable))
	}

	fn get_multiple_storages_verified<Header: HeaderTrait<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &Header,
	) -> Result<Vec<StorageEntryVerified<V>>, itp_ocall_api::Error> {
		let mut entries = Vec::with_capacity(storage_hashes.len());
		for hash in storage_hashes.into_iter() {
			let value = self
				.get_at_header(header, &hash)
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
