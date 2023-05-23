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

use crate::{ApiClientError, ApiResult};
use itp_api_client_types::{Block, SignedBlock};
use itp_types::{
	parentchain::{BlockNumber, Hash, Header, StorageProof},
	H256,
};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::traits::GetRuntimeBlockType;
use substrate_api_client::{
	rpc::Request, serde_impls::StorageKey, storage_key, Api, ExtrinsicParams, FrameSystemConfig,
	GetBlock, GetHeader, GetStorage,
};

type RawEvents = Vec<u8>;

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>>;
	fn signed_block(&self, hash: Option<Hash>) -> ApiResult<Option<SignedBlock>>;
	fn get_genesis_hash(&self) -> ApiResult<Hash>;
	fn header(&self, header_hash: Option<Hash>) -> ApiResult<Option<Header>>;
	/// Fetch blocks from parentchain with blocknumber from until to, including both boundaries.
	/// Returns a vector with one element if from equals to.
	/// Returns an empty vector if from is greater than to.
	fn get_blocks(&self, from: BlockNumber, to: BlockNumber) -> ApiResult<Vec<SignedBlock>>;
	fn is_grandpa_available(&self) -> ApiResult<bool>;
	fn grandpa_authorities(&self, hash: Option<H256>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<H256>) -> ApiResult<StorageProof>;
	fn get_events_value_proof(&self, block_hash: Option<H256>) -> ApiResult<StorageProof>;
	fn get_events_for_block(&self, block_hash: Option<H256>) -> ApiResult<RawEvents>;
}

impl<Signer, Client, Params, Runtime> ChainApi for Api<Signer, Client, Params, Runtime>
where
	Client: Request,
	Runtime: FrameSystemConfig<Hash = Hash, Header = Header, BlockNumber = BlockNumber>
		+ GetRuntimeBlockType<RuntimeBlock = Block>,
	Params: ExtrinsicParams<Runtime::Index, Runtime::Hash>,
{
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>> {
		self.get_finalized_head()?
			.map_or_else(|| Ok(None), |hash| self.signed_block(Some(hash)))
	}

	fn signed_block(&self, hash: Option<Hash>) -> ApiResult<Option<SignedBlock>> {
		Ok(self.get_signed_block(hash)?.map(|block| block.into()))
	}

	fn get_genesis_hash(&self) -> ApiResult<Hash> {
		self.get_block_hash(Some(0u32))?.ok_or(ApiClientError::BlockHashNotFound)
	}

	fn header(&self, header_hash: Option<Hash>) -> ApiResult<Option<Header>> {
		self.get_header(header_hash)
	}

	fn get_blocks(&self, from: BlockNumber, to: BlockNumber) -> ApiResult<Vec<SignedBlock>> {
		let mut blocks = Vec::<SignedBlock>::new();

		for n in from..=to {
			if let Some(block) = self.get_signed_block_by_num(Some(n))? {
				blocks.push(block.into());
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

	fn grandpa_authorities(&self, at_block: Option<Hash>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key_hash(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), at_block)?
			.map(|g: VersionedAuthorityList| g.into())
			.unwrap_or_default())
	}

	fn grandpa_authorities_proof(&self, at_block: Option<Hash>) -> ApiResult<StorageProof> {
		Ok(self
			.get_storage_proof_by_keys(
				vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
				at_block,
			)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}

	fn get_events_value_proof(&self, block_hash: Option<H256>) -> ApiResult<StorageProof> {
		let key = storage_key("System", "Events");
		Ok(self
			.get_storage_proof_by_keys(Vec::from([key]), block_hash)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}

	fn get_events_for_block(&self, block_hash: Option<H256>) -> ApiResult<RawEvents> {
		let key = storage_key("System", "Events");
		Ok(self.get_opaque_storage_by_key_hash(key, block_hash)?.unwrap_or_default())
	}
}
