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
use itp_types::{Header, SignedBlock};
use sp_core::{storage::StorageKey, Pair, H256};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, ExtrinsicParams, RpcClient};

pub type StorageProof = Vec<Vec<u8>>;

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>>;
	fn signed_block(&self, hash: Option<H256>) -> ApiResult<Option<SignedBlock>>;
	fn get_genesis_hash(&self) -> ApiResult<H256>;
	fn get_header(&self, header_hash: Option<H256>) -> ApiResult<Option<Header>>;
	/// Fetch blocks from parentchain with blocknumber from until to, including both boundaries.
	/// Returns a vector with one element if from equals to.
	/// Returns an empty vector if from is greater than to.
	fn get_blocks(&self, from: u32, to: u32) -> ApiResult<Vec<SignedBlock>>;
	fn is_grandpa_available(&self) -> ApiResult<bool>;
	fn grandpa_authorities(&self, hash: Option<H256>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<H256>) -> ApiResult<StorageProof>;
}

impl<P: Pair, Client: RpcClient, Params: ExtrinsicParams> ChainApi for Api<P, Client, Params>
where
	MultiSignature: From<P::Signature>,
{
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>> {
		self.get_finalized_head()?
			.map_or_else(|| Ok(None), |hash| self.signed_block(Some(hash)))
	}

	fn signed_block(&self, hash: Option<H256>) -> ApiResult<Option<SignedBlock>> {
		// Even though this is only a wrapper here, we want to have this in the trait
		// to be able to be generic over the trait and mock the `signed_block` method
		// in tests.
		self.get_signed_block(hash)
	}

	fn get_genesis_hash(&self) -> ApiResult<H256> {
		self.get_genesis_hash()
	}

	fn get_header(&self, header_hash: Option<H256>) -> ApiResult<Option<Header>> {
		self.get_header(header_hash)
	}

	fn get_blocks(&self, from: u32, to: u32) -> ApiResult<Vec<SignedBlock>> {
		let mut blocks = Vec::<SignedBlock>::new();

		for n in from..=to {
			if let Some(block) = self.get_signed_block_by_num(Some(n))? {
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

	fn grandpa_authorities(&self, at_block: Option<H256>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key_hash(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), at_block)?
			.map(|g: VersionedAuthorityList| g.into())
			.unwrap_or_default())
	}

	fn grandpa_authorities_proof(&self, at_block: Option<H256>) -> ApiResult<StorageProof> {
		Ok(self
			.get_storage_proof_by_keys(
				vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
				at_block,
			)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap_or_default())
	}
}
