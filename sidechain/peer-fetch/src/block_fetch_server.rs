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

use crate::error::Result;
use its_primitives::types::{BlockHash, ShardIdentifier, SignedBlock};
use its_rpc_handler::constants::RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER;
use its_storage::interface::FetchBlocks;
use jsonrpsee::{types::error::CallError, RpcModule};
use log::*;
use std::sync::Arc;

/// RPC server module builder for fetching sidechain blocks from peers.
pub struct BlockFetchServerModuleBuilder<FetchBlocksFromStorage> {
	sidechain_block_fetcher: Arc<FetchBlocksFromStorage>,
}

impl<FetchBlocksFromStorage> BlockFetchServerModuleBuilder<FetchBlocksFromStorage>
where
	// Have to use the concrete `SignedBlock` type, because the ShardIdentifier type
	// does not have the Serialize/Deserialize trait bound.
	FetchBlocksFromStorage: FetchBlocks<SignedBlock> + Send + Sync + 'static,
{
	pub fn new(sidechain_block_fetcher: Arc<FetchBlocksFromStorage>) -> Self {
		BlockFetchServerModuleBuilder { sidechain_block_fetcher }
	}

	pub fn build(self) -> Result<RpcModule<Arc<FetchBlocksFromStorage>>> {
		let mut fetch_sidechain_blocks_module = RpcModule::new(self.sidechain_block_fetcher);
		fetch_sidechain_blocks_module.register_method(
			RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER,
			|params, sidechain_block_fetcher| {
				debug!("{}: {:?}", RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER, params);

				let (from_block_hash, maybe_until_block_hash, shard_identifier) =
					params.one::<(BlockHash, Option<BlockHash>, ShardIdentifier)>()?;
				info!("Got request to fetch sidechain blocks from peer. Fetching sidechain blocks from storage \
					(last imported block hash: {:?}, until block hash: {:?}, shard: {}", 
					from_block_hash, maybe_until_block_hash, shard_identifier);

				match maybe_until_block_hash {
					Some(until_block_hash) => sidechain_block_fetcher
						.fetch_blocks_in_range(
							&from_block_hash,
							&until_block_hash,
							&shard_identifier,
						)
						.map_err(|e| {
							error!("Failed to fetch sidechain blocks from storage: {:?}", e);
							CallError::Failed(e.into())
						}),
					None => sidechain_block_fetcher
						.fetch_all_blocks_after(&from_block_hash, &shard_identifier)
						.map_err(|e| {
							error!("Failed to fetch sidechain blocks from storage: {:?}", e);
							CallError::Failed(e.into())
						}),
				}
			},
		)?;
		Ok(fetch_sidechain_blocks_module)
	}
}
