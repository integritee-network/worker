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

use crate::test::mocks::types::TestBlockImporter;
use codec::{Decode, Encode};
use itc_parentchain::primitives::ParentchainId;
use itp_ocall_api::{EnclaveOnChainOCallApi, EnclaveSidechainOCallApi, Result};
use itp_types::{
	storage::StorageEntryVerified, BlockHash, Header as ParentchainHeader, ShardIdentifier,
	WorkerRequest, WorkerResponse, H256,
};
use its_primitives::types::block::SignedBlock as SignedSidechainBlockType;
use its_sidechain::consensus_common::BlockImport;
use sgx_types::SgxResult;
use sp_runtime::{traits::Header as ParentchainHeaderTrait, OpaqueExtrinsic};
use std::{sync::Arc, vec::Vec};

/// OCallApi mock that routes the proposed sidechain blocks directly to the importer,
/// short circuiting all the RPC calls.
#[derive(Clone)]
pub struct ProposeToImportOCallApi {
	parentchain_header: ParentchainHeader,
	block_importer: Arc<TestBlockImporter>,
}

impl ProposeToImportOCallApi {
	pub fn new(
		parentchain_header: ParentchainHeader,
		block_importer: Arc<TestBlockImporter>,
	) -> Self {
		ProposeToImportOCallApi { parentchain_header, block_importer }
	}
}

impl EnclaveOnChainOCallApi for ProposeToImportOCallApi {
	fn send_to_parentchain(
		&self,
		_extrinsics: Vec<OpaqueExtrinsic>,
		_: &ParentchainId,
	) -> SgxResult<()> {
		Ok(())
	}

	fn worker_request<V: Encode + Decode>(
		&self,
		_req: Vec<WorkerRequest>,
		_: &ParentchainId,
	) -> SgxResult<Vec<WorkerResponse<V>>> {
		todo!()
	}

	fn get_storage_verified<H: ParentchainHeaderTrait<Hash = H256>, V: Decode>(
		&self,
		_storage_hash: Vec<u8>,
		_header: &H,
		_: &ParentchainId,
	) -> Result<StorageEntryVerified<V>> {
		todo!()
	}

	fn get_multiple_storages_verified<H: ParentchainHeaderTrait<Hash = H256>, V: Decode>(
		&self,
		_storage_hashes: Vec<Vec<u8>>,
		_header: &H,
		_: &ParentchainId,
	) -> Result<Vec<StorageEntryVerified<V>>> {
		todo!()
	}
}

impl EnclaveSidechainOCallApi for ProposeToImportOCallApi {
	fn propose_sidechain_blocks<SignedSidechainBlock: Encode>(
		&self,
		signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()> {
		let decoded_signed_blocks: Vec<SignedSidechainBlockType> = signed_blocks
			.iter()
			.map(|sb| sb.encode())
			.map(|e| SignedSidechainBlockType::decode(&mut e.as_slice()).unwrap())
			.collect();

		for signed_block in decoded_signed_blocks {
			self.block_importer
				.import_block(signed_block, &self.parentchain_header)
				.unwrap();
		}
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
