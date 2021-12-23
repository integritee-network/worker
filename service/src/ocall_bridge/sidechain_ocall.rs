/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::{
	global_peer_updater::UpdateWorkerPeers,
	ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, SidechainBridge},
	sync_block_gossiper::GossipBlocks,
};
use codec::Decode;
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use its_storage::BlockStorage;
use log::*;
use std::sync::Arc;

pub struct SidechainOCall<BlockGossiper, Storage, PeerUpdater> {
	block_gossiper: Arc<BlockGossiper>,
	block_storage: Arc<Storage>,
	peer_updater: Arc<PeerUpdater>,
}

impl<BlockGossiper, Storage, PeerUpdater> SidechainOCall<BlockGossiper, Storage, PeerUpdater> {
	pub fn new(
		block_gossiper: Arc<BlockGossiper>,
		block_storage: Arc<Storage>,
		peer_updater: Arc<PeerUpdater>,
	) -> Self {
		SidechainOCall { block_gossiper, block_storage, peer_updater }
	}
}

impl<BlockGossiper, Storage, PeerUpdater> SidechainBridge
	for SidechainOCall<BlockGossiper, Storage, PeerUpdater>
where
	BlockGossiper: GossipBlocks,
	Storage: BlockStorage<SignedSidechainBlock>,
	PeerUpdater: UpdateWorkerPeers,
{
	fn propose_sidechain_blocks(&self, signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()> {
		// TODO: improve error handling, using a mut status is not good design?
		let mut status: OCallBridgeResult<()> = Ok(());

		// handle blocks
		let signed_blocks: Vec<SignedSidechainBlock> =
			match Decode::decode(&mut signed_blocks_encoded.as_slice()) {
				Ok(blocks) => blocks,
				Err(_) => {
					status = Err(OCallBridgeError::ProposeSidechainBlock(
						"Could not decode signed blocks".to_string(),
					));
					vec![]
				},
			};

		if !signed_blocks.is_empty() {
			info!(
				"Enclave produced sidechain blocks: {:?}",
				signed_blocks.iter().map(|b| b.block.block_number).collect::<Vec<u64>>()
			);
		} else {
			debug!("Enclave did not produce sidechain blocks");
		}

		if let Err(e) = self.peer_updater.update_peers() {
			error!("Error gossiping blocks: {:?}", e);
			// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
			// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		}

		if let Err(e) = self.block_gossiper.gossip_blocks(signed_blocks) {
			error!("Error gossiping blocks: {:?}", e);
			// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
			// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		}

		status
	}

	fn store_sidechain_blocks(&self, signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()> {
		// TODO: improve error handling, using a mut status is not good design?
		let mut status: OCallBridgeResult<()> = Ok(());

		let signed_blocks: Vec<SignedSidechainBlock> =
			match Decode::decode(&mut signed_blocks_encoded.as_slice()) {
				Ok(blocks) => blocks,
				Err(_) => {
					status = Err(OCallBridgeError::ProposeSidechainBlock(
						"Could not decode signed blocks".to_string(),
					));
					vec![]
				},
			};

		if let Err(e) = self.block_storage.store_blocks(signed_blocks) {
			error!("Error storing blocks: {:?}", e);
		}

		status
	}
}
