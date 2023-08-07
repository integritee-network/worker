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
use itp_types::{
	parentchain::Hash, AccountId, IpfsHash, MultiEnclave, ShardIdentifier, ShardStatus,
};
use substrate_api_client::{
	log::error, rpc::Request, Api, ExtrinsicParams, FrameSystemConfig, GetStorage,
};

pub const TEEREX: &str = "Teerex";
pub const ENCLAVE_BRIDGE: &str = "EnclaveBridge";

/// ApiClient extension that enables communication with the `teerex` pallet.
pub trait PalletTeerexApi {
	fn enclave(
		&self,
		account: &AccountId,
		at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>>;
	fn enclave_count(&self, at_block: Option<Hash>) -> ApiResult<u64>;
	fn all_enclaves(&self, at_block: Option<Hash>) -> ApiResult<Vec<MultiEnclave<Vec<u8>>>>;
	fn primary_worker_for_shard(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>>;
	fn latest_ipfs_hash(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<IpfsHash>>;
}

impl<Signer, Client, Params, Runtime> PalletTeerexApi for Api<Signer, Client, Params, Runtime>
where
	Client: Request,
	Runtime: FrameSystemConfig<Hash = Hash>,
	Params: ExtrinsicParams<Runtime::Index, Runtime::Hash>,
{
	fn enclave(
		&self,
		account: &AccountId,
		at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
		self.get_storage_map(TEEREX, "SovereignEnclaves", account, at_block)
	}

	fn enclave_count(&self, at_block: Option<Hash>) -> ApiResult<u64> {
		Ok(self.all_enclaves(at_block)?.len() as u64)
	}

	fn all_enclaves(&self, at_block: Option<Hash>) -> ApiResult<Vec<MultiEnclave<Vec<u8>>>> {
		let key_prefix = self.get_storage_map_key_prefix("Teerex", "SovereignEnclaves")?;
		//fixme: solve this properly with infinite elements
		let max_keys = 1000;
		let storage_keys =
			self.get_storage_keys_paged(Some(key_prefix), max_keys, None, at_block)?;

		if storage_keys.len() == max_keys as usize {
			error!("results can be wrong because max keys reached for query")
		}
		let enclaves = storage_keys
			.iter()
			.filter_map(|key| self.get_storage_by_key_hash(key.clone(), at_block).ok()?)
			.collect();
		Ok(enclaves)
	}

	fn primary_worker_for_shard(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
		self.get_storage_map(ENCLAVE_BRIDGE, "ShardStatus", shard, at_block)?
			.map_or_else(
				|| Ok(None),
				|statuses: ShardStatus| {
					statuses.get(0).map_or_else(
						|| Ok(None),
						|signerstatus| self.enclave(&signerstatus.signer, at_block),
					)
				},
			)
	}

	fn latest_ipfs_hash(
		&self,
		shard: &ShardIdentifier,
		at_block: Option<Hash>,
	) -> ApiResult<Option<IpfsHash>> {
		self.get_storage_map(TEEREX, "LatestIPFSHash", shard, at_block)
	}
}
