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
use itp_types::{Enclave, IpfsHash, ShardIdentifier};
use sp_core::{Pair, H256 as Hash};
use sp_runtime::MultiSignature;
use substrate_api_client::{Api, RpcClient};

pub const TEEREX: &str = "Teerex";
pub const SIDECHAIN: &str = "Sidechain";

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
		self.get_storage_map(SIDECHAIN, "WorkerForShard", shard, at_block)?
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
