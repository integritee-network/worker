use async_trait::async_trait;
use jsonrpsee::{
    types::{to_json_value, traits::Client},
    ws_client::WsClientBuilder,
};
use log::info;
use std::sync::Arc;

use substratee_api_client_extensions::SubstrateeRegistryApi;
// use substratee_worker_api::direct_client::WorkerToWorkerApi;
use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;

use crate::config::Config;
use crate::error::Error;
use std::num::ParseIntError;
use substratee_node_primitives::Enclave as EnclaveMetadata;

pub type WorkerResult<T> = Result<T, Error>;

pub struct Worker<Config, NodeApi, Enclave, WorkerApiDirect> {
    config: Config,
    node_api: NodeApi,
    _enclave_api: Enclave,
    _worker_api_direct: Arc<WorkerApiDirect>,
}

impl<Config, NodeApi, Enclave, WorkerApiDirect> Worker<Config, NodeApi, Enclave, WorkerApiDirect> {
    pub fn new(
        config: Config,
        node_api: NodeApi,
        _enclave_api: Enclave,
        _worker_api_direct: WorkerApiDirect,
    ) -> Self {
        Self {
            config,
            node_api,
            _enclave_api,
            _worker_api_direct: Arc::new(_worker_api_direct),
        }
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
    NodeApi: SubstrateeRegistryApi + Send + Sync,
    Enclave: Send + Sync,
    WorkerApiDirect: Send + Sync,
{
    async fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
        let peers = self.peers()?;
        info!("Gossiping sidechain blocks to peers: {:?}", peers);

        for p in peers.iter() {
            // Todo: once this is the two direct servers are merged, remove this.
            let url = worker_url_into_async_rpc_port(&p.url)?;
            info!("Gossiping block to peer with address: {:?}", url);
            let client = WsClientBuilder::default().build(&url).await?;
            let response: Vec<u8> = client
                .request(
                    "sidechain_importBlock",
                    vec![to_json_value(blocks.clone())?].into(),
                )
                .await?;
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
pub fn worker_url_into_async_rpc_port(url: &str) -> WorkerResult<String> {
    // [Option("ws"), //ip, port]
    let mut url_vec: Vec<&str> = url.split(":").collect();
    match url_vec.len() {
        3 | 2 => (),
        _ => Err(Error::Custom("Invalid worker url format".into()))?,
    };

    let ip = if url_vec.len() == 3 {
        format!("{}:{}", url_vec.remove(0), url_vec.remove(0))
    } else {
        url_vec.remove(0).into()
    };

    let port: i32 = url_vec.remove(0).parse().map_err(|e:ParseIntError| Error::Custom(e.into()))?;

    Ok(format!("{}:{}", ip, (port + 1)))
}

#[cfg(test)]
mod tests {
    use jsonrpsee::{ws_server::WsServerBuilder, RpcModule};
    use log::debug;
    use std::net::SocketAddr;
    use substratee_worker_primitives::block::SignedBlock as SignedSidechainBlock;
    use tokio::net::ToSocketAddrs;

    use crate::tests::{
        commons::{local_worker_config, test_sidechain_block},
        mock::{TestNodeApi, W1_URL, W2_URL},
    };
    use crate::worker::{Worker, WorkerT};

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    async fn run_server(addr: impl ToSocketAddrs) -> anyhow::Result<SocketAddr> {
        let mut server = WsServerBuilder::default().build(addr).await?;
        let mut module = RpcModule::new(());

        module.register_method("sidechain_importBlock", |params, _| {
            debug!("sidechain_importBlock params: {:?}", params);
            let blocks: Vec<SignedSidechainBlock> = params.one()?;
            Ok(blocks)
        })?;

        server.register_module(module).unwrap();

        let socket_addr = server.local_addr()?;
        tokio::spawn(async move { server.start().await });
        Ok(socket_addr)
    }

    #[tokio::test]
    async fn gossip_blocks_works() {
        init();
        run_server(W2_URL).await.unwrap();

        let worker = Worker::new(local_worker_config(W1_URL.into()), TestNodeApi, (), ());

        worker
            .gossip_blocks(vec![test_sidechain_block()])
            .await
            .unwrap();
    }
}
