use itp_types::{Enclave, IpfsHash, ShardIdentifier};
use sp_core::{Pair, H256 as Hash};
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, RpcClient};

use crate::ApiResult;

pub const TEEREX: &str = "Teerex";

/// ApiClient extension that enables communication with the `teerex` pallet.
pub trait PalletTeerexApi {
	fn enclave(&self, index: u64, at_block: Option<Hash>) -> ApiResult<Option<Enclave>>;
	fn enclave_count(&self, at_block: Option<Hash>) -> ApiResult<u64>;
	fn all_enclaves(&self, at_block: Option<Hash>) -> ApiResult<Vec<Enclave>>;
	fn worker_for_shard(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<Enclave>>;
	fn latest_ipfs_hash(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<IpfsHash>>;
}

impl<P: Pair, Client: RpcClient> PalletTeerexApi for Api<P, Client>
where
	MultiSignature: From<P::Signature>,
{
	fn enclave(&self, index: u64, at_block: Option<Hash>) -> ApiResult<Option<Enclave>> {
		self.get_storage_map(TEEREX, "EnclaveRegistry", index, at_block)
	}

	fn enclave_count(&self, at_block: Option<Hash>) -> ApiResult<u64> {
		Ok(self.get_storage_value(TEEREX, "EnclaveCount", at_block)?.unwrap_or(0u64))
	}

	fn all_enclaves(&self, at_block: Option<Hash>) -> ApiResult<Vec<Enclave>> {
		let count = self.enclave_count(at_block)?;
		let mut enclaves = Vec::with_capacity(count as usize);
		for n in 1..=count {
			enclaves.push(self.enclave(n, at_block)?.unwrap())
		}
		Ok(enclaves)
	}

	fn worker_for_shard(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<Enclave>> {
		self.get_storage_map(TEEREX, "WorkerForShard", shard, at_block)?
			.map_or_else(|| Ok(None), |w_index| self.enclave(w_index, at_block))
	}

	fn latest_ipfs_hash(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<IpfsHash>> {
		self.get_storage_map(TEEREX, "LatestIPFSHash", shard, at_block)
	}
}
