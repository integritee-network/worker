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

use crate::{error::Result, FetchBlocksFromPeer};
use async_trait::async_trait;
use itc_rpc_client::url_utils::worker_url_into_async_rpc_url;
use itp_api_client_extensions::PalletTeerexApi;
use its_primitives::{
	constants::RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER,
	traits::SignedBlock as SignedBlockTrait,
	types::{BlockHash, ShardIdentifier},
};
use jsonrpsee::{
	types::to_json_value,
	ws_client::{traits::Client, WsClientBuilder},
};
use serde::de::DeserializeOwned;
use std::marker::PhantomData;

/// Sidechain peer block fetcher implementation.
///
/// Determines from which peer validateer to fetch blocks from and sends the RPC request
/// to retrieve the blocks.
pub struct PeerFetcher<SignedBlock, NodeApi> {
	node_api: NodeApi,
	_phantom: PhantomData<SignedBlock>,
}

impl<SignedBlock, NodeApi> PeerFetcher<SignedBlock, NodeApi>
where
	SignedBlock: SignedBlockTrait + DeserializeOwned,
	NodeApi: PalletTeerexApi + Send + Sync,
{
	pub fn new(node_api: NodeApi) -> Self {
		PeerFetcher { node_api, _phantom: Default::default() }
	}

	pub fn get_peer_rpc_url_to_sync_from(&self) -> Result<String> {
		// TODO: Get the validateer to sync from (author of the last sidechain block)
		let all_validateers = self.node_api.all_enclaves()?;
		let sync_source = all_validateers.first().unwrap().url.clone();

		worker_url_into_async_rpc_url(sync_source.as_str()).map_err(|e| e.into())
	}
}

#[async_trait]
impl<SignedBlock, NodeApi> FetchBlocksFromPeer for PeerFetcher<SignedBlock, NodeApi>
where
	SignedBlock: SignedBlockTrait + DeserializeOwned,
	NodeApi: PalletTeerexApi + Send + Sync,
{
	type SignedBlockType = SignedBlock;

	async fn fetch_blocks_from_peer(
		&self,
		last_known_block_hash: BlockHash,
		shard_identifier: ShardIdentifier,
	) -> Result<Vec<Self::SignedBlockType>> {
		let sync_source_rpc_url = self.get_peer_rpc_url_to_sync_from()?;

		let rpc_parameters = vec![to_json_value((last_known_block_hash, shard_identifier))?];

		let client = WsClientBuilder::default().build(sync_source_rpc_url.as_str()).await?;

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

	// use super::*;
	// use jsonrpsee::{ws_server::WsServerBuilder, RpcModule};
	// use log::*;
	// use std::{net::SocketAddr, sync::Arc};
	// use tokio::net::ToSocketAddrs;
	//
	// const W1_URL: &str = "127.0.0.1:2233";

	// fn init() {
	// 	let _ = env_logger::builder().is_test(true).try_init();
	// }

	// TODO write a test where we setup a server using the builder from `peer_fetch_server`

	// async fn run_server(addr: impl ToSocketAddrs) -> anyhow::Result<SocketAddr> {
	// 	let mut server = WsServerBuilder::default().build(addr).await?;
	// 	let mut module = RpcModule::new(());
	//
	// 	module.register_method(RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER, |params, _| {
	// 		debug!("{} params: {:?}", RPC_METHOD_NAME_FETCH_BLOCKS_FROM_PEER, params);
	// 		let _blocks: Vec<SignedSidechainBlock> = params.one()?;
	// 		Ok("ok".as_bytes().to_vec())
	// 	})?;
	//
	// 	server.register_module(module).unwrap();
	//
	// 	let socket_addr = server.local_addr()?;
	// 	tokio::spawn(async move { server.start().await });
	// 	Ok(socket_addr)
	// }
	//
	// #[tokio::test]
	// async fn gossip_blocks_works() {
	// 	init();
	// 	run_server(worker_url_into_async_rpc_url(W1_URL).unwrap()).await.unwrap();
	// 	run_server(worker_url_into_async_rpc_url(W2_URL).unwrap()).await.unwrap();
	//
	// 	let worker = Worker::new(local_worker_config(W1_URL.into()), TestNodeApi, Arc::new(()), ());
	//
	// 	let resp = worker
	// 		.gossip_blocks(vec![SidechainBlockBuilder::default().build_signed()])
	// 		.await;
	// 	assert_ok!(resp);
	// }
}
