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
use itp_ocall_api::{EnclaveOnChainOCallApi, EnclaveSidechainOCallApi};
use itp_types::{Header as ParentchainHeader, WorkerRequest, WorkerResponse};
use its_sidechain::{
	consensus_common::BlockImport, primitives::types::SignedBlock as SignedSidechainBlock,
};
use sgx_types::SgxResult;
use sp_runtime::OpaqueExtrinsic;
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
	fn send_to_parentchain(&self, _extrinsics: Vec<OpaqueExtrinsic>) -> SgxResult<()> {
		Ok(())
	}

	fn worker_request<V: Encode + Decode>(
		&self,
		_req: Vec<WorkerRequest>,
	) -> SgxResult<Vec<WorkerResponse<V>>> {
		todo!()
	}
}

impl EnclaveSidechainOCallApi for ProposeToImportOCallApi {
	fn propose_sidechain_blocks<SB: Encode>(&self, signed_blocks: Vec<SB>) -> SgxResult<()> {
		let decoded_signed_blocks: Vec<SignedSidechainBlock> = signed_blocks
			.iter()
			.map(|sb| sb.encode())
			.map(|e| SignedSidechainBlock::decode(&mut e.as_slice()).unwrap())
			.collect();

		for signed_block in decoded_signed_blocks {
			self.block_importer
				.import_block(signed_block, &self.parentchain_header)
				.unwrap()
		}
		Ok(())
	}

	fn store_sidechain_blocks<SB: Encode>(&self, _signed_blocks: Vec<SB>) -> SgxResult<()> {
		Ok(())
	}
}
