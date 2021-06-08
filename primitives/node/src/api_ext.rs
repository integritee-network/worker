use sp_core::crypto::Pair;

pub use my_node_runtime::{
	substratee_registry::{Enclave as EnclaveGen, ShardIdentifier},
	AccountId,
};
use substrate_api_client::{Api, ApiClientError};
use sp_runtime::MultiSignature;


pub type ApiResult<T> = Result<T, ApiClientError>;
pub type Enclave = EnclaveGen<AccountId, Vec<u8>>;
pub type IpfsHash = [u8; 46];

/// ApiClient extension that enables communication with the `substratee-registry` pallet.
pub trait SubstrateeRegistryApi {
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>>;
	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>>;
	fn worker_for_shard(&self, shard: &ShardIdentifier) -> ApiResult<Option<Enclave>>;
	fn enclave_count(&self) -> ApiResult<u64>;
	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<IpfsHash>>;
}

/// Simple ApiClient extension that contains some convenience methods.
pub trait ApiClientExt {
	fn get_nonce_of(&self, who: &AccountId) -> ApiResult<u32>;
	fn get_free_balance(&self, who: &AccountId) -> ApiResult<u128>;
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


impl<P: Pair> SubstrateeRegistryApi for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>> {
		self.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", index, None)
	}

	fn all_enclaves(&self) -> ApiResult<Vec<Enclaves>> {
		let count = self.enclave_count()?;
		let mut enclaves = Vec::with_capacity(count as usize);
		for n in 1..=count {
			enclaves.push(self.enclave(n)?)
		}
		Ok(enclaves)
	}

	fn worker_for_shard(&self, shard: &ShardIdentifier) -> ApiResult<Option<Enclave>> {
		self.get_storage_map("SubstrateeRegistry", "WorkerForShard", shard, None)?
			.map_or_else(|| Ok(None), |w_index| self.enclave(w_index))
	}

	fn enclave_count(&self) -> ApiResult<u64> {
		Ok(self.get_storage_value("SubstrateeRegistry", "EnclaveCount", None)?
			.unwrap_or(0u64))
	}

	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<[u8; 46]>> {
		self.get_storage_map("SubstrateeRegistry", "LatestIPFSHash", shard, None)
	}
}