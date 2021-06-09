use log::info;
use sp_core::sr25519;
use std::sync::Arc;
use std::sync::mpsc::channel;
use substrate_api_client::{Api, XtStatus};
use substratee_api_client_extensions::SubstrateeRegistryApi;

use substratee_worker_primitives::block::{SignedBlock as SignedSidechainBlock};

use crate::error::Error;
use crate::utils::hex_encode;
use crate::config::Config;

pub type WorkerResult<T> = Result<T, Error>;

pub struct Worker<Config, NodeApi, Enclave, WorkerApiDirect> {
	config: Config,
	node_api: NodeApi,
	_enclave_api: Enclave,
	_worker_api_direct: Arc<WorkerApiDirect>,
}

pub trait Ocall {
	fn send_confirmations(&self, confirms: Vec<Vec<u8>>) -> WorkerResult<()>;
	fn gossip_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()>;
}

// todo make generic over api also, but for this, we need to hide sending extrinsics behind a trait
impl<Enclave, WorkerApiDirect> Ocall for Worker<Config, Api<sr25519::Pair>, Enclave, WorkerApiDirect> {
	fn send_confirmations(&self, confirms: Vec<Vec<u8>>) -> WorkerResult<()> {
		if !confirms.is_empty() {
			println!("Enclave wants to send {} extrinsics", confirms.len());

			for call in confirms.into_iter() {
				self.node_api.send_extrinsic(hex_encode(call), XtStatus::Ready)?;
			}
			// await next block to avoid #37
			let (events_in, events_out) = channel();
			self.node_api.subscribe_events(events_in)?;
			let _ = events_out.recv().unwrap();
			let _ = events_out.recv().unwrap();
			// FIXME: we should unsubscribe here or the thread will throw a SendError because the channel is destroyed
		}
		Ok(())
	}

	fn gossip_blocks(&self, _blocks: Vec<SignedSidechainBlock>) -> WorkerResult<()> {
		let mut peers = self.node_api.all_enclaves()?;
		peers.retain(|e| e.url != self.config.worker_url().as_bytes().to_vec());

		info!("Gossiping sidechain blocks to peers: {:?}", peers);
		Ok(())
	}
}