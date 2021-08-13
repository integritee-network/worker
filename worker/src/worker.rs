///! Substratee worker. Inspiration for this design came from parity's substrate Client.
///
/// This should serve as a proof of concept for a potential refactoring design. Ultimately, everything
/// from the main.rs should be covered by the worker struct here - hidden and split across
/// multiple traits.
use async_trait::async_trait;
use jsonrpsee::{
	types::{to_json_value, traits::Client},
	ws_client::WsClientBuilder,
};
use log::info;
use std::num::ParseIntError;

use substratee_api_client_extensions::PalletTeerexApi;
use substratee_node_primitives::Enclave as EnclaveMetadata;
use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;

use crate::{config::Config, error::Error};
use std::sync::Arc;

pub type WorkerResult<T> = Result<T, Error>;

// don't put any trait bounds here. It is good practise to only enforce them where needed. This
// also serves a guide when traits should be split into subtraits.
pub struct Worker<Config, NodeApi, Enclave, WorkerApiDirect> {
	config: Config,
	node_api: NodeApi, // todo: Depending on system design, all the api fields should be Arc<Api>
	// unused yet, but will be used when more methods are migrated to the worker
	_enclave_api: Arc<Enclave>,
	_worker_api_direct: WorkerApiDirect,
}

impl<Config, NodeApi, Enclave, WorkerApiDirect> Worker<Config, NodeApi, Enclave, WorkerApiDirect> {
	pub fn new(
		config: Config,
		node_api: NodeApi,
		_enclave_api: Arc<Enclave>,
		_worker_api_direct: WorkerApiDirect,
	) -> Self {
		Self { config, node_api, _enclave_api, _worker_api_direct }
	}

	// will soon be used.
	#[allow(dead_code)]
	pub fn node_api(&self) -> &NodeApi {
		&self.node_api
	}
}

#[async_trait]
pub trait WorkerT {
	// fn send_confirmations(&self, confirms: Vec<Vec<u8>>) -> WorkerResult<()>;
	async fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
	fn peers(&self) -> WorkerResult<Vec<EnclaveMetadata>>;
}

#[async_trait]
impl<NodeApi, Enclave, WorkerApiDirect> WorkerT
	for Worker<Config, NodeApi, Enclave, WorkerApiDirect>
where
	NodeApi: PalletTeerexApi + Send + Sync,
	Enclave: Send + Sync,
	WorkerApiDirect: Send + Sync,
{
	async fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
		let peers = self.peers()?;
		info!("Gossiping sidechain blocks to peers: {:?}", peers);

		for p in peers.iter() {
			// Todo: once the two direct servers are merged, remove this.
			let url = worker_url_into_async_rpc_url(&p.url)?;
			info!("Gossiping block to peer with address: {:?}", url);
			let client = WsClientBuilder::default().build(&url).await?;
			let response: String = client
				.request::<Vec<u8>>(
					"sidechain_importBlock",
					vec![to_json_value(blocks.clone())?].into(),
				)
				.await
				.map(String::from_utf8)??;
			info!("sidechain_importBlock response: {:?}", response);
		}
		Ok(())
	}

	fn peers(&self) -> WorkerResult<Vec<EnclaveMetadata>> {
		let mut peers = self.node_api.all_enclaves()?;
		peers.retain(|e| e.url.trim_start_matches("ws://") != self.config.worker_url());
		Ok(peers)
	}
}

/// Temporary method that transforms the workers rpc port of the direct api defined in rpc/direct_client
/// to the new version in rpc/server. Remove this, when all the methods have been migrated to the new one
/// in rpc/server.
pub fn worker_url_into_async_rpc_url(url: &str) -> WorkerResult<String> {
	// [Option("ws"), //ip, port]
	let mut url_vec: Vec<&str> = url.split(':').collect();
	match url_vec.len() {
		3 | 2 => (),
		_ => return Err(Error::Custom("Invalid worker url format".into())),
	};

	let ip = if url_vec.len() == 3 {
		format!("{}:{}", url_vec.remove(0), url_vec.remove(0))
	} else {
		url_vec.remove(0).into()
	};

	let port: i32 =
		url_vec.remove(0).parse().map_err(|e: ParseIntError| Error::Custom(e.into()))?;

	Ok(format!("{}:{}", ip, (port + 1)))
}

#[cfg(test)]
mod tests {
	use frame_support::assert_ok;
	use jsonrpsee::{ws_server::WsServerBuilder, RpcModule};
	use log::debug;
	use std::net::SocketAddr;
	use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;
	use tokio::net::ToSocketAddrs;

	use crate::{
		tests::{
			commons::{local_worker_config, test_sidechain_block},
			mock::{TestNodeApi, W1_URL, W2_URL},
		},
		worker::{worker_url_into_async_rpc_url, Worker, WorkerT},
	};
	use std::sync::Arc;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	async fn run_server(addr: impl ToSocketAddrs) -> anyhow::Result<SocketAddr> {
		let mut server = WsServerBuilder::default().build(addr).await?;
		let mut module = RpcModule::new(());

		module.register_method("sidechain_importBlock", |params, _| {
			debug!("sidechain_importBlock params: {:?}", params);
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
		run_server(worker_url_into_async_rpc_url(W2_URL).unwrap()).await.unwrap();

		let worker = Worker::new(local_worker_config(W1_URL.into()), TestNodeApi, Arc::new(()), ());

		let resp = worker.gossip_blocks(vec![test_sidechain_block()]).await;
		assert_ok!(resp);
	}
}
