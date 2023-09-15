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
use itp_api_client_types::{
	storage_key,
	traits::{GetChainInfo, GetStorage},
	Api, Config, Request, StorageKey,
};
use itp_types::parentchain::{BlockNumber, StorageProof};
use sp_consensus_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::generic::SignedBlock as GenericSignedBlock;

type RawEvents = Vec<u8>;

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	type Hash;
	type Block;
	type Header;
	type BlockNumber;

	fn last_finalized_block(&self) -> ApiResult<Option<GenericSignedBlock<Self::Block>>>;
	fn signed_block(
		&self,
		hash: Option<Self::Hash>,
	) -> ApiResult<Option<GenericSignedBlock<Self::Block>>>;
	fn get_genesis_hash(&self) -> ApiResult<Self::Hash>;
	fn header(&self, header_hash: Option<Self::Hash>) -> ApiResult<Option<Self::Header>>;
	/// Fetch blocks from parentchain with blocknumber from until to, including both boundaries.
	/// Returns a vector with one element if from equals to.
	/// Returns an empty vector if from is greater than to.
	fn get_blocks(
		&self,
		from: Self::BlockNumber,
		to: Self::BlockNumber,
	) -> ApiResult<Vec<GenericSignedBlock<Self::Block>>>;
	fn is_grandpa_available(&self) -> ApiResult<bool>;
	fn grandpa_authorities(&self, hash: Option<Self::Hash>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<Self::Hash>) -> ApiResult<StorageProof>;
	fn get_events_value_proof(&self, block_hash: Option<Self::Hash>) -> ApiResult<StorageProof>;
	fn get_events_for_block(&self, block_hash: Option<Self::Hash>) -> ApiResult<RawEvents>;
}

impl<RuntimeConfig, Client> ChainApi for Api<RuntimeConfig, Client>
where
	RuntimeConfig: Config<BlockNumber = BlockNumber>,
	Client: Request,
{
	type Hash = RuntimeConfig::Hash;
	type Header = RuntimeConfig::Header;
	type Block = RuntimeConfig::Block;
	type BlockNumber = RuntimeConfig::BlockNumber;

	fn last_finalized_block(&self) -> ApiResult<Option<GenericSignedBlock<Self::Block>>> {
		self.get_finalized_head()?
			.map_or_else(|| Ok(None), |hash| self.signed_block(Some(hash)))
	}

	fn signed_block(
		&self,
		hash: Option<Self::Hash>,
	) -> ApiResult<Option<GenericSignedBlock<Self::Block>>> {
		Ok(self.get_signed_block(hash)?.map(|block| block.into()))
	}

	fn get_genesis_hash(&self) -> ApiResult<Self::Hash> {
		self.get_block_hash(Some(0u32))?.ok_or(ApiClientError::BlockHashNotFound)
	}

	fn header(&self, header_hash: Option<Self::Hash>) -> ApiResult<Option<Self::Header>> {
		self.get_header(header_hash)
	}

	fn get_blocks(
		&self,
		from: Self::BlockNumber,
		to: Self::BlockNumber,
	) -> ApiResult<Vec<GenericSignedBlock<Self::Block>>> {
		let mut blocks = Vec::<GenericSignedBlock<Self::Block>>::new();

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
			.get_storage_by_key(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), genesis_hash)?
			.map(|v: VersionedAuthorityList| v.into())
			.map(|v: AuthorityList| !v.is_empty())
			.unwrap_or(false))
	}

	fn grandpa_authorities(&self, at_block: Option<Self::Hash>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), at_block)?
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

	fn get_events_value_proof(&self, block_hash: Option<Self::Hash>) -> ApiResult<StorageProof> {
		let key = storage_key("System", "Events");
		Ok(self
			.get_storage_proof_by_keys(Vec::from([key]), block_hash)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}

	fn get_events_for_block(&self, block_hash: Option<Self::Hash>) -> ApiResult<RawEvents> {
		let key = storage_key("System", "Events");
		Ok(self.get_opaque_storage_by_key(key, block_hash)?.unwrap_or_default())
	}
}
