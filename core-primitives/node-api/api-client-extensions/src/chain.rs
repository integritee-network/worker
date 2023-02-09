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

use crate::ApiResult;
use my_node_runtime::{Block, BlockNumber, Hash as H256, Header};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use substrate_api_client::{
	primitives::{SignedBlock as SignedBlockG, StorageKey},
	GetBlock, GetHeader, GetStorage,
};

pub type StorageProof = Vec<Vec<u8>>;

type SignedBlock = SignedBlockG<Block>;

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	type Hash: Clone;

	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>>;
	fn signed_block(&self, hash: Option<Self::Hash>) -> ApiResult<Option<SignedBlock>>;
	fn get_genesis_hash(&self) -> ApiResult<Self::Hash>;
	fn get_header(&self, header_hash: Option<Self::Hash>) -> ApiResult<Option<Header>>;
	/// Fetch blocks from parentchain with blocknumber from until to, including both boundaries.
	/// Returns a vector with one element if from equals to.
	/// Returns an empty vector if from is greater than to.
	fn get_blocks(&self, from: u32, to: u32) -> ApiResult<Vec<SignedBlock>>;
	fn is_grandpa_available(&self) -> ApiResult<bool>;
	fn grandpa_authorities(&self, hash: Option<Self::Hash>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<Self::Hash>) -> ApiResult<StorageProof>;
}

impl<Api> ChainApi for Api
where
	Api: GetHeader<H256, Header = Header>,
	Api: GetBlock<BlockNumber, H256, Block = Block>,
	Api: GetStorage<H256>,
{
	type Hash = H256;

	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>> {
		self.get_finalized_head()?
			.map_or_else(|| Ok(None), |hash| self.signed_block(Some(hash)))
	}

	fn signed_block(&self, hash: Option<Self::Hash>) -> ApiResult<Option<SignedBlock>> {
		// Even though this is only a wrapper here, we want to have this in the trait
		// to be able to be generic over the trait and mock the `signed_block` method
		// in tests.
		self.get_signed_block(hash)
	}

	fn get_genesis_hash(&self) -> ApiResult<Self::Hash> {
		if let Some(hash) = self.get_block_hash(Some(0u32.into()))? {
			Ok(hash)
		} else {
			Err(substrate_api_client::api::Error::FetchGenesisHash)
		}
	}

	fn get_header(&self, header_hash: Option<Self::Hash>) -> ApiResult<Option<Header>> {
		self.get_header(header_hash)
	}

	fn get_blocks(&self, from: u32, to: u32) -> ApiResult<Vec<SignedBlock>> {
		let mut blocks = Vec::<SignedBlock>::new();

		for n in from..=to {
			if let Some(block) = self.get_signed_block_by_num(Some(n.into()))? {
				blocks.push(block);
			}
		}
		Ok(blocks)
	}

	fn is_grandpa_available(&self) -> ApiResult<bool> {
		let genesis_hash = Some(self.get_genesis_hash().expect("Failed to get genesis hash"));
		Ok(self
			.get_storage_by_key_hash(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), genesis_hash)?
			.map(|v: VersionedAuthorityList| v.into())
			.map(|v: AuthorityList| !v.is_empty())
			.unwrap_or(false))
	}

	fn grandpa_authorities(&self, at_block: Option<Self::Hash>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key_hash(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), at_block)?
			.map(|g: VersionedAuthorityList| g.into())
			.unwrap_or_default())
	}

	fn grandpa_authorities_proof(&self, at_block: Option<Self::Hash>) -> ApiResult<StorageProof> {
		Ok(self
			.get_storage_proof_by_keys(
				vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
				at_block,
			)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}
}
