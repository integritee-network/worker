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

///! Integritee worker. Inspiration for this design came from parity's substrate Client.
///
/// This should serve as a proof of concept for a potential refactoring design. Ultimately, everything
/// from the main.rs should be covered by the worker struct here - hidden and split across
/// multiple traits.
use crate::{config::Config, error::Error};
use async_trait::async_trait;
use itc_rpc_client::direct_client::{DirectApi, DirectClient as DirectWorkerApi};
use itp_node_api_extensions::PalletTeerexApi;
use its_primitives::{
	constants::RPC_METHOD_NAME_IMPORT_BLOCKS, types::SignedBlock as SignedSidechainBlock,
};
use jsonrpsee::{
	types::{to_json_value, traits::Client},
	ws_client::WsClientBuilder,
};
use log::*;
use std::sync::Arc;

pub type WorkerResult<T> = Result<T, Error>;
pub type Url = String;
pub struct Worker<Config, NodeApi, Enclave> {
	_config: Config,
	node_api: NodeApi, // todo: Depending on system design, all the api fields should be Arc<Api>
	// unused yet, but will be used when more methods are migrated to the worker
	_enclave_api: Arc<Enclave>,
	peers: Vec<Url>,
}

impl<Config, NodeApi, Enclave> Worker<Config, NodeApi, Enclave> {
	pub fn new(
		_config: Config,
		node_api: NodeApi,
		_enclave_api: Arc<Enclave>,
		peers: Vec<Url>,
	) -> Self {
		Self { _config, node_api, _enclave_api, peers }
	}

	// will soon be used.
	#[allow(dead_code)]
	pub fn node_api(&self) -> &NodeApi {
		&self.node_api
	}
}

#[async_trait]
/// Gossip Sidechain blocks to peers.
pub trait AsyncBlockGossiper {
	async fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
}

#[async_trait]
impl<NodeApi, Enclave> AsyncBlockGossiper for Worker<Config, NodeApi, Enclave>
where
	NodeApi: PalletTeerexApi + Send + Sync,
	Enclave: Send + Sync,
{
	async fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
		if blocks.is_empty() {
			debug!("No blocks to gossip, returning");
			return Ok(())
		}

		let blocks_json = vec![to_json_value(blocks)?];

		for url in self.peers.iter().cloned() {
			let blocks = blocks_json.clone();

			tokio::spawn(async move {
				debug!("Gossiping block to peer with address: {:?}", url);
				// FIXME: Websocket connection to a worker should stay, once established.
				let client = match WsClientBuilder::default().build(&url).await {
					Ok(c) => c,
					Err(e) => {
						error!("Failed to create websocket client for block gossiping (target url: {}): {:?}", url, e);
						return
					},
				};

				if let Err(e) =
					client.request::<Vec<u8>>(RPC_METHOD_NAME_IMPORT_BLOCKS, blocks.into()).await
				{
					error!(
						"Gossip block request ({}) to {} failed: {:?}",
						RPC_METHOD_NAME_IMPORT_BLOCKS, url, e
					);
				}
			});
		}
		Ok(())
	}
}

/// Looks for new peers and updates them.
pub trait UpdatePeers {
	fn search_peers(&self) -> WorkerResult<Vec<Url>>;
	fn set_peers(&mut self, peers: Vec<Url>) -> WorkerResult<()>;
	fn update_peers(&mut self) -> WorkerResult<()> {
		let peers = self.search_peers()?;
		self.set_peers(peers)
	}
}

impl<NodeApi, Enclave> UpdatePeers for Worker<Config, NodeApi, Enclave>
where
	NodeApi: PalletTeerexApi + Send + Sync,
{
	fn search_peers(&self) -> WorkerResult<Vec<String>> {
		let enclaves = self.node_api.all_enclaves(None)?;
		let mut peer_urls = Vec::<String>::new();
		for enclave in enclaves {
			// FIXME: This is temporary only, as block gossiping should be moved to trusted ws server.
			let worker_api_direct = DirectWorkerApi::new(enclave.url);
			peer_urls.push(worker_api_direct.get_untrusted_worker_url()?);
		}
		Ok(peer_urls)
	}

	fn set_peers(&mut self, peers: Vec<Url>) -> WorkerResult<()> {
		self.peers = peers;
		Ok(())
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		tests::{
			commons::local_worker_config,
			mock::{TestNodeApi, W1_URL, W2_URL},
		},
		worker::{AsyncBlockGossiper, Worker},
	};
	use frame_support::assert_ok;
	use its_primitives::types::SignedBlock as SignedSidechainBlock;
	use its_test::sidechain_block_builder::SidechainBlockBuilder;
	use jsonrpsee::{ws_server::WsServerBuilder, RpcModule};
	use log::debug;
	use std::{net::SocketAddr, sync::Arc};
	use tokio::net::ToSocketAddrs;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	async fn run_server(addr: impl ToSocketAddrs) -> anyhow::Result<SocketAddr> {
		let mut server = WsServerBuilder::default().build(addr).await?;
		let mut module = RpcModule::new(());

		module.register_method(RPC_METHOD_NAME_IMPORT_BLOCKS, |params, _| {
			debug!("{} params: {:?}", RPC_METHOD_NAME_IMPORT_BLOCKS, params);
			let _blocks: Vec<SignedSidechainBlock> = params.one()?;
			Ok("ok".as_bytes().to_vec())
		})?;

		server.register_module(module).unwrap();

		let socket_addr = server.local_addr()?;
		tokio::spawn(async move { server.start().await });
		Ok(socket_addr)
	}

	#[tokio::test]
	async fn gossip_blocks_works() {
		init();
		run_server(W1_URL).await.unwrap();
		run_server(W2_URL).await.unwrap();
		let untrusted_worker_port = "4000".to_string();
		let peers = vec![format!("ws://{}", W1_URL), format!("ws://{}", W2_URL)];

		let worker = Worker::new(
			local_worker_config(W1_URL.into(), untrusted_worker_port.clone(), "30".to_string()),
			TestNodeApi,
			Arc::new(()),
			peers,
		);

		let resp = worker
			.gossip_blocks(vec![SidechainBlockBuilder::default().build_signed()])
			.await;
		assert_ok!(resp);
	}
}
