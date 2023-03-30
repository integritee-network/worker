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
use itp_api_client_types::{Block, SignedBlock};
use itp_types::parentchain::{BlockNumber, Hash, Header, StorageProof};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::{traits::GetRuntimeBlockType, DeserializeOwned};
use substrate_api_client::{
	api::Error::NoBlockHash, primitives::StorageKey, rpc::Request, Api, ExtrinsicParams,
	FrameSystemConfig, GetBlock, GetHeader, GetStorage,
};

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
	fn grandpa_authorities(&self, hash: Option<Hash>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<Hash>) -> ApiResult<StorageProof>;
}

impl<Signer, Client, Params, Runtime> ChainApi for Api<Signer, Client, Params, Runtime>
where
	Client: Request,
	Runtime: FrameSystemConfig + GetRuntimeBlockType,
	Params: ExtrinsicParams<Runtime::Index, Runtime::Hash>,
	Runtime::Header: DeserializeOwned + Into<Header>,
	Runtime::Hash: From<Hash> + Into<Hash>,
	Runtime::RuntimeBlock: DeserializeOwned + Into<Block>,
	Runtime::BlockNumber: Into<u32>,
{
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>> {
		self.get_finalized_head()?
			.map_or_else(|| Ok(None), |hash| self.signed_block(Some(hash.into())))
	}

	fn signed_block(&self, hash: Option<Hash>) -> ApiResult<Option<SignedBlock>> {
		// Convert the substrate-api-clients `SignedBlock` redefinition into ours.
		let maybe_signed_block = self.get_signed_block(hash.map(|h| h.into()))?;
		let maybe_converted_block = match maybe_signed_block {
			Some(block) => Some(convert_signed_block::<Runtime>(block)),
			None => None,
		};
		Ok(maybe_converted_block)
	}

	fn get_genesis_hash(&self) -> ApiResult<Hash> {
		if let Some(hash) = self.get_block_hash(Some(0u32.into()))? {
			Ok(hash.into())
		} else {
			Err(NoBlockHash)
		}
	}

	fn header(&self, header_hash: Option<Hash>) -> ApiResult<Option<Header>> {
		Ok(self.get_header(header_hash.map(|h| h.into()))?.map(Into::into))
	}

	fn get_blocks(&self, from: BlockNumber, to: BlockNumber) -> ApiResult<Vec<SignedBlock>> {
		let mut blocks = Vec::<SignedBlock>::new();

		for n in from..=to {
			if let Some(block) = self.get_signed_block_by_num(Some(n.into()))? {
				blocks.push(convert_signed_block::<Runtime>(block));
			}
		}
		Ok(blocks)
	}

	fn is_grandpa_available(&self) -> ApiResult<bool> {
		let genesis_hash = Some(self.get_genesis_hash().expect("Failed to get genesis hash"));
		Ok(self
			.get_storage_by_key_hash(
				StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()),
				genesis_hash.map(|b| b.into()),
			)?
			.map(|v: VersionedAuthorityList| v.into())
			.map(|v: AuthorityList| !v.is_empty())
			.unwrap_or(false))
	}

	fn grandpa_authorities(&self, at_block: Option<Hash>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key_hash(
				StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()),
				at_block.map(|b| b.into()),
			)?
			.map(|g: VersionedAuthorityList| g.into())
			.unwrap_or_default())
	}

	fn grandpa_authorities_proof(&self, at_block: Option<Hash>) -> ApiResult<StorageProof> {
		Ok(self
			.get_storage_proof_by_keys(
				vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
				at_block.map(|b| b.into()),
			)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}
}

fn convert_signed_block<Runtime>(
	signed_block: substrate_api_client::SignedBlock<Runtime::RuntimeBlock>,
) -> SignedBlock
where
	Runtime: GetRuntimeBlockType,
	Runtime::RuntimeBlock: Into<Block>,
{
	SignedBlock {
		block: signed_block.block.into(),
		justifications: signed_block.justifications.map(|justifactions| justifactions.into()),
	}
}
