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
use crate::{config::Config, error::Error, TrackInitialization};
use async_trait::async_trait;
use itc_rpc_client::direct_client::{DirectApi, DirectClient as DirectWorkerApi};
use itp_node_api::{api_client::PalletTeerexApi, node_api_factory::CreateNodeApi};
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_rpc_handler::constants::RPC_METHOD_NAME_IMPORT_BLOCKS;
use jsonrpsee::{
	types::{to_json_value, traits::Client},
	ws_client::WsClientBuilder,
};
use log::*;
use std::sync::{Arc, RwLock};

pub type WorkerResult<T> = Result<T, Error>;
pub type Url = String;
pub struct Worker<Config, NodeApiFactory, Enclave, InitializationHandler> {
	_config: Config,
	// unused yet, but will be used when more methods are migrated to the worker
	_enclave_api: Arc<Enclave>,
	node_api_factory: Arc<NodeApiFactory>,
	initialization_handler: Arc<InitializationHandler>,
	peers: RwLock<Vec<Url>>,
}

impl<Config, NodeApiFactory, Enclave, InitializationHandler>
	Worker<Config, NodeApiFactory, Enclave, InitializationHandler>
{
	pub fn new(
		config: Config,
		enclave_api: Arc<Enclave>,
		node_api_factory: Arc<NodeApiFactory>,
		initialization_handler: Arc<InitializationHandler>,
		peers: Vec<Url>,
	) -> Self {
		Self {
			_config: config,
			_enclave_api: enclave_api,
			node_api_factory,
			initialization_handler,
			peers: RwLock::new(peers),
		}
	}
}

#[async_trait]
/// Broadcast Sidechain blocks to peers.
pub trait AsyncBlockBroadcaster {
	async fn broadcast_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
}

#[async_trait]
impl<NodeApiFactory, Enclave, InitializationHandler> AsyncBlockBroadcaster
	for Worker<Config, NodeApiFactory, Enclave, InitializationHandler>
where
	NodeApiFactory: CreateNodeApi + Send + Sync,
	Enclave: Send + Sync,
	InitializationHandler: TrackInitialization + Send + Sync,
{
	async fn broadcast_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
		if blocks.is_empty() {
			debug!("No blocks to broadcast, returning");
			return Ok(())
		}

		let blocks_json = vec![to_json_value(blocks)?];
		let peers = self
			.peers
			.read()
			.map_err(|e| {
				Error::Custom(format!("Encountered poisoned lock for peers: {:?}", e).into())
			})
			.map(|l| l.clone())?;

		self.initialization_handler.sidechain_block_produced();

		for url in peers {
			let blocks = blocks_json.clone();

			tokio::spawn(async move {
				debug!("Broadcasting block to peer with address: {:?}", url);
				// FIXME: Websocket connection to a worker should stay, once established.
				let client = match WsClientBuilder::default().build(&url).await {
					Ok(c) => c,
					Err(e) => {
						error!("Failed to create websocket client for block broadcasting (target url: {}): {:?}", url, e);
						return
					},
				};

				if let Err(e) =
					client.request::<Vec<u8>>(RPC_METHOD_NAME_IMPORT_BLOCKS, blocks.into()).await
				{
					error!(
						"Broadcast block request ({}) to {} failed: {:?}",
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

	fn set_peers(&self, peers: Vec<Url>) -> WorkerResult<()>;

	fn update_peers(&self) -> WorkerResult<()> {
		let peers = self.search_peers()?;
		self.set_peers(peers)
	}
}

impl<NodeApiFactory, Enclave, InitializationHandler> UpdatePeers
	for Worker<Config, NodeApiFactory, Enclave, InitializationHandler>
where
	NodeApiFactory: CreateNodeApi + Send + Sync,
{
	fn search_peers(&self) -> WorkerResult<Vec<String>> {
		let node_api = self
			.node_api_factory
			.create_api()
			.map_err(|e| Error::Custom(format!("Failed to create NodeApi: {:?}", e).into()))?;
		let enclaves = node_api.all_enclaves(None)?;
		let mut peer_urls = Vec::<String>::new();
		for enclave in enclaves {
			// FIXME: This is temporary only, as block broadcasting should be moved to trusted ws server.
			let enclave_url = String::from_utf8(enclave.instance_url().unwrap()).unwrap();
			let worker_api_direct = DirectWorkerApi::new(enclave_url.clone());
			match worker_api_direct.get_untrusted_worker_url() {
				Ok(untrusted_worker_url) => {
					peer_urls.push(untrusted_worker_url);
				},
				Err(e) => {
					error!(
						"Failed to get untrusted worker url (enclave: {}): {:?}",
						enclave_url, e
					);
				},
			}
		}
		Ok(peer_urls)
	}

	fn set_peers(&self, peers: Vec<Url>) -> WorkerResult<()> {
		let mut peers_lock = self.peers.write().map_err(|e| {
			Error::Custom(format!("Encountered poisoned lock for peers: {:?}", e).into())
		})?;
		*peers_lock = peers;
		Ok(())
	}
}
#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		tests::{
			commons::local_worker_config,
			mock::{W1_URL, W2_URL},
			mocks::initialization_handler_mock::TrackInitializationMock,
		},
		worker::{AsyncBlockBroadcaster, Worker},
	};
	use frame_support::assert_ok;
	use itp_node_api::node_api_factory::NodeApiFactory;
	use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
	use its_test::sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait};
	use jsonrpsee::{ws_server::WsServerBuilder, RpcModule};
	use log::debug;
	use sp_keyring::AccountKeyring;
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
	async fn broadcast_blocks_works() {
		init();
		run_server(W1_URL).await.unwrap();
		run_server(W2_URL).await.unwrap();
		let untrusted_worker_port = "4000".to_string();
		let peers = vec![format!("ws://{}", W1_URL), format!("ws://{}", W2_URL)];

		let worker = Worker::new(
			local_worker_config(W1_URL.into(), untrusted_worker_port.clone(), "30".to_string()),
			Arc::new(()),
			Arc::new(NodeApiFactory::new(
				"ws://invalid.url".to_string(),
				AccountKeyring::Alice.pair(),
			)),
			Arc::new(TrackInitializationMock {}),
			peers,
		);

		let resp = worker
			.broadcast_blocks(vec![SidechainBlockBuilder::default().build_signed()])
			.await;
		assert_ok!(resp);
	}
}
