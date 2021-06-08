use my_node_runtime::{AccountId, substratee_registry::Enclave as EnclaveGen};
use sp_runtime::MultiSignature;
use substrate_api_client::Api;
use sp_core::Pair;

use crate::{ShardIdentifier, ApiResult};

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