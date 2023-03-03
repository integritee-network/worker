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

use crate::{error::Result, untrusted_peer_fetch::FetchUntrustedPeers, FetchBlocksFromPeer};
use async_trait::async_trait;
use its_primitives::{
	traits::SignedBlock as SignedBlockTrait,
	types::{BlockHash, ShardIdentifier},
};
use its_rpc_handler::constants::RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER;
use jsonrpsee::{
	types::to_json_value,
	ws_client::{traits::Client, WsClientBuilder},
};
use log::info;
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

/// Sidechain block fetcher implementation.
///
/// Fetches block from a peer with an RPC request.
pub struct BlockFetcher<SignedBlock, PeerFetcher> {
	peer_fetcher: PeerFetcher,
	_phantom: PhantomData<SignedBlock>,
}

impl<SignedBlock, PeerFetcher> BlockFetcher<SignedBlock, PeerFetcher>
where
	SignedBlock: SignedBlockTrait + DeserializeOwned,
	PeerFetcher: FetchUntrustedPeers + Send + Sync,
{
	pub fn new(peer_fetcher: PeerFetcher) -> Self {
		BlockFetcher { peer_fetcher, _phantom: Default::default() }
	}
}

#[async_trait]
impl<SignedBlock, PeerFetcher> FetchBlocksFromPeer for BlockFetcher<SignedBlock, PeerFetcher>
where
	SignedBlock: SignedBlockTrait + DeserializeOwned,
	PeerFetcher: FetchUntrustedPeers + Send + Sync,
{
	type SignedBlockType = SignedBlock;

	async fn fetch_blocks_from_peer(
		&self,
		last_imported_block_hash: BlockHash,
		maybe_until_block_hash: Option<BlockHash>,
		shard_identifier: ShardIdentifier,
	) -> Result<Vec<Self::SignedBlockType>> {
		let sync_source_rpc_url =
			self.peer_fetcher.get_untrusted_peer_url_of_shard(&shard_identifier)?;

		let rpc_parameters = vec![to_json_value((
			last_imported_block_hash,
			maybe_until_block_hash,
			shard_identifier,
		))?];

		info!("Got untrusted url for peer block fetching: {}", sync_source_rpc_url);

		let client = WsClientBuilder::default().build(sync_source_rpc_url.as_str()).await?;

		info!("Sending fetch blocks from peer request");

		client
			.request::<Vec<SignedBlock>>(
				RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER,
				rpc_parameters.into(),
			)
			.await
			.map_err(|e| e.into())
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::{
		block_fetch_server::BlockFetchServerModuleBuilder,
		mocks::untrusted_peer_fetch_mock::UntrustedPeerFetcherMock,
	};
	use its_primitives::types::block::SignedBlock;
	use its_storage::fetch_blocks_mock::FetchBlocksMock;
	use its_test::sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait};
	use jsonrpsee::ws_server::WsServerBuilder;
	use std::{net::SocketAddr, sync::Arc};

	async fn run_server(
		blocks: Vec<SignedBlock>,
		web_socket_url: &str,
	) -> anyhow::Result<SocketAddr> {
		let mut server = WsServerBuilder::default().build(web_socket_url).await?;

		let storage_block_fetcher = Arc::new(FetchBlocksMock::default().with_blocks(blocks));
		let module = BlockFetchServerModuleBuilder::new(storage_block_fetcher).build().unwrap();

		server.register_module(module).unwrap();

		let socket_addr = server.local_addr()?;
		tokio::spawn(async move { server.start().await });
		Ok(socket_addr)
	}

	#[tokio::test]
	async fn fetch_blocks_without_bounds_from_peer_works() {
		const W1_URL: &str = "127.0.0.1:2233";

		let blocks_to_fetch = vec![
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
		];
		run_server(blocks_to_fetch.clone(), W1_URL).await.unwrap();

		let peer_fetch_mock = UntrustedPeerFetcherMock::new(format!("ws://{}", W1_URL));

		let peer_fetcher_client = BlockFetcher::<SignedBlock, _>::new(peer_fetch_mock);

		let blocks_fetched = peer_fetcher_client
			.fetch_blocks_from_peer(BlockHash::default(), None, ShardIdentifier::default())
			.await
			.unwrap();

		assert_eq!(blocks_to_fetch, blocks_fetched);
	}
}
