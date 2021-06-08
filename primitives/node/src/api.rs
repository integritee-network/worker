use sp_core::crypto::Pair;

pub use my_node_runtime::{
	substratee_registry::{Enclave as EnclaveGen, ShardIdentifier},
	AccountId,
};
use substrate_api_client::Api;
use sp_runtime::MultiSignature;


pub type Enclave = EnclaveGen<AccountId, Vec<u8>>;
pub type IpfsHash = [u8; 46];

/// ApiClient extension that enables communication with the `substratee-registry` pallet.
pub trait SubstrateeRegistryApi {
	fn enclave(&self, index: u64) -> Option<Enclave>;
	fn worker_for_shard(&self, shard: &ShardIdentifier) -> Option<Enclave>;
	fn enclave_count(&self) -> u64;
	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> Option<IpfsHash>;
}

/// Simple ApiClient extension that contains some convenience methods.
pub trait ApiClientExt {
	fn get_nonce_of(&self, who: &AccountId) -> u32;
	fn get_free_balance(&self, who: &AccountId) -> u128;
}

impl<P: Pair> ApiClientExt for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn get_nonce_of(&self, who: &AccountId) -> u32 {
		self.get_account_info(who)
			.unwrap()
			.map_or_else(|| 0, |info| info.nonce)
	}

	fn get_free_balance(&self, who: &AccountId) -> u128 {
		self.get_account_data(who)
			.unwrap()
			.map_or_else(|| 0, |data| data.free)
	}
}


impl<P: Pair> SubstrateeRegistryApi for Api<P>
	where
		MultiSignature: From<P::Signature>
{
	fn enclave(&self, index: u64) -> Option<Enclave> {
		self.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", index, None)
			.unwrap()
	}

	fn worker_for_shard(&self, shard: &ShardIdentifier) -> Option<Enclave> {
		self.get_storage_map("SubstrateeRegistry", "WorkerForShard", shard, None)
			.unwrap()
			.and_then(|w| self.enclave(w))
	}

	fn enclave_count(&self) -> u64 {
		self.get_storage_value("SubstrateeRegistry", "EnclaveCount", None)
			.unwrap()
			.unwrap_or(0u64)
	}

	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> Option<[u8; 46]> {
		self.get_storage_map("SubstrateeRegistry", "LatestIPFSHash", shard, None)
			.unwrap()
	}
}