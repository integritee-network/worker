use sp_core::Pair;
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, RpcClient};
use substratee_node_primitives::{Enclave, IpfsHash, ShardIdentifier};

use crate::ApiResult;

pub const TEEREX: &str = "Teerex";

/// ApiClient extension that enables communication with the `substratee-registry` pallet.
pub trait PalletTeerexApi {
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>>;
	fn enclave_count(&self) -> ApiResult<u64>;
	fn all_enclaves(&self) -> ApiResult<Vec<Enclave>>;
	fn worker_for_shard(&self, shard: &ShardIdentifier) -> ApiResult<Option<Enclave>>;
	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<IpfsHash>>;
}

impl<P: Pair, Client: RpcClient> PalletTeerexApi for Api<P, Client>
where
	MultiSignature: From<P::Signature>,
{
	fn enclave(&self, index: u64) -> ApiResult<Option<Enclave>> {
		self.get_storage_map(TEEREX, "EnclaveRegistry", index, None)
	}

	fn enclave_count(&self) -> ApiResult<u64> {
		Ok(self.get_storage_value(TEEREX, "EnclaveCount", None)?.unwrap_or(0u64))
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
		self.get_storage_map(TEEREX, "WorkerForShard", shard, None)?
			.map_or_else(|| Ok(None), |w_index| self.enclave(w_index))
	}

	fn latest_ipfs_hash(&self, shard: &ShardIdentifier) -> ApiResult<Option<IpfsHash>> {
		self.get_storage_map(TEEREX, "LatestIPFSHash", shard, None)
	}
}
