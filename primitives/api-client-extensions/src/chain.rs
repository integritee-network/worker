use sp_core::{storage::StorageKey, Pair, H256};
use sp_finality_grandpa::{AuthorityList, VersionedAuthorityList, GRANDPA_AUTHORITIES_KEY};
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, RpcClient};

use substratee_node_primitives::SignedBlock;

use crate::ApiResult;

pub type StorageProof = Vec<Vec<u8>>;

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>>;
	fn signed_block(&self, hash: Option<H256>) -> ApiResult<Option<SignedBlock>>;
	fn grandpa_authorities(&self, hash: Option<H256>) -> ApiResult<AuthorityList>;
	fn grandpa_authorities_proof(&self, hash: Option<H256>) -> ApiResult<StorageProof>;
}

impl<P: Pair, Client: RpcClient> ChainApi for Api<P, Client>
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

	fn grandpa_authorities(&self, at_block: Option<H256>) -> ApiResult<AuthorityList> {
		Ok(self
			.get_storage_by_key_hash(StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec()), at_block)?
			.map(|g: VersionedAuthorityList| g.into())
			.unwrap()) // todo: Introduce an error instead of unwrap: See: https://github.com/scs/substrate-api-client/issues/123
	}

	fn grandpa_authorities_proof(&self, at_block: Option<H256>) -> ApiResult<StorageProof> {
		Ok(self
			.get_storage_proof_by_keys(
				vec![StorageKey(GRANDPA_AUTHORITIES_KEY.to_vec())],
				at_block,
			)?
			.map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect())
			.unwrap()) // todo: Introduce an error instead of unwrap: See: https://github.com/scs/substrate-api-client/issues/123
	}
}
