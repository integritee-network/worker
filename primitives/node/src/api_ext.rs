use sp_core::crypto::Pair;

pub use my_node_runtime::{
	substratee_registry::{Enclave as EnclaveGen, ShardIdentifier},
	AccountId,
};
use substrate_api_client::{Api, ApiClientError};
use sp_runtime::MultiSignature;
use my_node_runtime::SignedBlock;
use sp_core::H256;


pub type ApiResult<T> = Result<T, ApiClientError>;
pub type Enclave = EnclaveGen<AccountId, Vec<u8>>;
pub type IpfsHash = [u8; 46];

/// ApiClient extension that enables communication with the `substratee-registry` pallet.
pub trait SubstrateeRegistryApi {
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>>;
	fn enclave_count(&self) -> ApiResult<u64>;
	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>>;
	fn worker_for_shard(&self, shard: &ShardIdentifier) -> ApiResult<Option<Enclave>>;
	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<IpfsHash>>;
}

/// Simple ApiClient extension that contains some convenience methods.
pub trait ApiClientExt {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128>;
}

/// ApiClient extension that simplifies chain data access.
pub trait ChainApi {
	fn last_finalized_block(&self) -> ApiResult<Option<SignedBlock>>;
	fn signed_block(&self, hash: Option<H256>) -> ApiResult<Option<SignedBlock>>;
}

impl<P: Pair> ApiClientExt for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32> {
		Ok(self.get_account_info(who)?
			.map_or_else(|| 0, |info| info.nonce))
	}

	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128> {
		Ok(self.get_account_data(who)?
			.map_or_else(|| 0, |data| data.free))
	}
}

impl<P: Pair> ChainApi for Api<P>
	where
		MultiSignature: From<P::Signature>
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
}


impl<P: Pair> SubstrateeRegistryApi for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>> {
		self.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", index, None)
	}

	fn enclave_count(&self) -> ApiResult<u64> {
		Ok(self.get_storage_value("SubstrateeRegistry", "EnclaveCount", None)?
			.unwrap_or(0u64))
	}

	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>> {
		let count = self.enclave_count()?;
		let mut enclaves = Vec::with_capacity(count as usize);
		for n in 1..=count {
			enclaves.push(self.enclave(n)?.unwrap())
		}
		Ok(enclaves)
	}

	fn worker_for_shard(&self, shard: &ShardIdentifier) -> ApiResult<Option<Enclave>> {
		self.get_storage_map("SubstrateeRegistry", "WorkerForShard", shard, None)?
			.map_or_else(|| Ok(None), |w_index| self.enclave(w_index))
	}

	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<[u8; 46]>> {
		self.get_storage_map("SubstrateeRegistry", "LatestIPFSHash", shard, None)
	}
}