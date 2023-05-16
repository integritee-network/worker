/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use itc_parentchain_test::{ParentchainBlockBuilder, ParentchainHeaderBuilder};
use itp_node_api::api_client::{ApiResult, ChainApi, SignedBlock};
use itp_types::{
	parentchain::{Hash, Header, StorageProof},
	H256,
};
use sp_finality_grandpa::AuthorityList;

pub struct ParentchainApiMock {
	parentchain: Vec<SignedBlock>,
}

impl ParentchainApiMock {
	pub(crate) fn new() -> Self {
		ParentchainApiMock { parentchain: Vec::new() }
	}

	/// Initializes parentchain with a default block chain of a given length.
	pub fn with_default_blocks(mut self, number_of_blocks: u32) -> Self {
		self.parentchain = (1..=number_of_blocks)
			.map(|n| {
				let header = ParentchainHeaderBuilder::default().with_number(n).build();
				ParentchainBlockBuilder::default().with_header(header).build_signed()
			})
			.collect();
		self
	}
}

impl ChainApi for ParentchainApiMock {
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>> {
		Ok(self.parentchain.last().cloned())
	}

	fn signed_block(&self, _hash: Option<Hash>) -> ApiResult<Option<SignedBlock>> {
		todo!()
	}

	fn get_genesis_hash(&self) -> ApiResult<Hash> {
		todo!()
	}

	fn header(&self, _header_hash: Option<Hash>) -> ApiResult<Option<Header>> {
		todo!()
	}

	fn get_blocks(&self, from: u32, to: u32) -> ApiResult<Vec<SignedBlock>> {
		let num_elements = to.checked_sub(from).map(|n| n + 1).unwrap_or(0);
		let blocks = self
			.parentchain
			.iter()
			.skip(from as usize)
			.take(num_elements as usize)
			.cloned()
			.collect();
		ApiResult::Ok(blocks)
	}

	fn is_grandpa_available(&self) -> ApiResult<bool> {
		todo!()
	}

	fn grandpa_authorities(&self, _hash: Option<Hash>) -> ApiResult<AuthorityList> {
		todo!()
	}

	fn grandpa_authorities_proof(&self, _hash: Option<Hash>) -> ApiResult<StorageProof> {
		todo!()
	}

	fn get_events_value_proof(&self, _block_hash: Option<H256>) -> ApiResult<StorageProof> {
		Ok(Default::default())
	}

	fn get_events_for_block(&self, _block_hash: Option<H256>) -> ApiResult<Vec<u8>> {
		Ok(Default::default())
	}
}
