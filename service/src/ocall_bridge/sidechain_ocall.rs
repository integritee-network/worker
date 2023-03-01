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
	ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, SidechainBridge},
	sync_block_broadcaster::BroadcastBlocks,
	worker_peers_updater::UpdateWorkerPeers,
	GetTokioHandle,
};
use codec::{Decode, Encode};
use itp_types::{BlockHash, ShardIdentifier};
use its_peer_fetch::FetchBlocksFromPeer;
use its_primitives::{traits::Block, types::SignedBlock as SignedSidechainBlock};
use its_storage::BlockStorage;
use log::*;
use std::sync::Arc;

pub struct SidechainOCall<BlockBroadcaster, Storage, PeerUpdater, PeerBlockFetcher, TokioHandle> {
	block_broadcaster: Arc<BlockBroadcaster>,
	block_storage: Arc<Storage>,
	peer_updater: Arc<PeerUpdater>,
	peer_block_fetcher: Arc<PeerBlockFetcher>,
	tokio_handle: Arc<TokioHandle>,
}

impl<BlockBroadcaster, Storage, PeerUpdater, PeerBlockFetcher, TokioHandle>
	SidechainOCall<BlockBroadcaster, Storage, PeerUpdater, PeerBlockFetcher, TokioHandle>
{
	pub fn new(
		block_broadcaster: Arc<BlockBroadcaster>,
		block_storage: Arc<Storage>,
		peer_updater: Arc<PeerUpdater>,
		peer_block_fetcher: Arc<PeerBlockFetcher>,
		tokio_handle: Arc<TokioHandle>,
	) -> Self {
		SidechainOCall {
			block_broadcaster,
			block_storage,
			peer_updater,
			peer_block_fetcher,
			tokio_handle,
		}
	}
}

impl<BlockBroadcaster, Storage, PeerUpdater, PeerBlockFetcher, TokioHandle> SidechainBridge
	for SidechainOCall<BlockBroadcaster, Storage, PeerUpdater, PeerBlockFetcher, TokioHandle>
where
	BlockBroadcaster: BroadcastBlocks,
	Storage: BlockStorage<SignedSidechainBlock>,
	PeerUpdater: UpdateWorkerPeers,
	PeerBlockFetcher: FetchBlocksFromPeer<SignedBlockType = SignedSidechainBlock>,
	TokioHandle: GetTokioHandle,
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
				signed_blocks
					.iter()
					.map(|b| b.block.header().block_number)
					.collect::<Vec<u64>>()
			);
		} else {
			debug!("Enclave did not produce sidechain blocks");
		}

		// FIXME: When & where should peers be updated?
		debug!("Updating peers..");
		if let Err(e) = self.peer_updater.update_peers() {
			error!("Error updating peers: {:?}", e);
		// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
		// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		} else {
			info!("Successfully updated peers");
		}

		debug!("Broadcasting sidechain blocks ...");
		if let Err(e) = self.block_broadcaster.broadcast_blocks(signed_blocks) {
			error!("Error broadcasting blocks: {:?}", e);
		// Fixme: returning an error here results in a `HeaderAncestryMismatch` error.
		// status = sgx_status_t::SGX_ERROR_UNEXPECTED;
		} else {
			info!("Successfully broadcast blocks");
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

	fn fetch_sidechain_blocks_from_peer(
		&self,
		last_imported_block_hash_encoded: Vec<u8>,
		maybe_until_block_hash_encoded: Vec<u8>,
		shard_identifier_encoded: Vec<u8>,
	) -> OCallBridgeResult<Vec<u8>> {
		let last_imported_block_hash: BlockHash =
			Decode::decode(&mut last_imported_block_hash_encoded.as_slice()).map_err(|_| {
				OCallBridgeError::FetchSidechainBlocksFromPeer(
					"Failed to decode last imported block hash".to_string(),
				)
			})?;

		let maybe_until_block_hash: Option<BlockHash> =
			Decode::decode(&mut maybe_until_block_hash_encoded.as_slice()).map_err(|_| {
				OCallBridgeError::FetchSidechainBlocksFromPeer(
					"Failed to decode optional until block hash".to_string(),
				)
			})?;

		let shard_identifier: ShardIdentifier =
			Decode::decode(&mut shard_identifier_encoded.as_slice()).map_err(|_| {
				OCallBridgeError::FetchSidechainBlocksFromPeer(
					"Failed to decode shard identifier".to_string(),
				)
			})?;

		info!("[O-call] fetching blocks from peer..");

		let tokio_handle = self.tokio_handle.get_handle();

		let signed_sidechain_blocks = tokio_handle
			.block_on(self.peer_block_fetcher.fetch_blocks_from_peer(
				last_imported_block_hash,
				maybe_until_block_hash,
				shard_identifier,
			))
			.map_err(|e| {
				OCallBridgeError::FetchSidechainBlocksFromPeer(format!(
					"Failed to execute block fetching from peer: {:?}",
					e
				))
			})?;

		info!("[O-call] successfully fetched {} blocks from peer", signed_sidechain_blocks.len());

		Ok(signed_sidechain_blocks.encode())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		globals::tokio_handle::ScopedTokioHandle,
		tests::mocks::{
			broadcast_blocks_mock::BroadcastBlocksMock,
			update_worker_peers_mock::UpdateWorkerPeersMock,
		},
	};
	use codec::Decode;
	use its_peer_fetch::mocks::fetch_blocks_from_peer_mock::FetchBlocksFromPeerMock;
	use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
	use its_storage::{interface::BlockStorage, Result as StorageResult};
	use its_test::sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait};
	use primitive_types::H256;
	use std::{collections::HashMap, vec::Vec};

	struct BlockStorageMock;
	impl BlockStorage<SignedSidechainBlock> for BlockStorageMock {
		fn store_blocks(&self, _blocks: Vec<SignedSidechainBlock>) -> StorageResult<()> {
			Ok(())
		}
	}

	type TestSidechainOCall = SidechainOCall<
		BroadcastBlocksMock,
		BlockStorageMock,
		UpdateWorkerPeersMock,
		FetchBlocksFromPeerMock<SignedSidechainBlock>,
		ScopedTokioHandle,
	>;

	#[test]
	fn fetch_sidechain_blocks_from_peer_works() {
		let last_imported_block_hash = H256::random();
		let until_block_hash: Option<H256> = None;
		let shard_identifier = H256::random();
		let blocks = vec![
			SidechainBlockBuilder::random().build_signed(),
			SidechainBlockBuilder::random().build_signed(),
		];
		let peer_blocks_map = HashMap::from([(shard_identifier, blocks.clone())]);
		let sidechain_ocall = setup_sidechain_ocall_with_peer_blocks(peer_blocks_map);

		let fetched_blocks_encoded = sidechain_ocall
			.fetch_sidechain_blocks_from_peer(
				last_imported_block_hash.encode(),
				until_block_hash.encode(),
				shard_identifier.encode(),
			)
			.unwrap();

		let fetched_blocks_decoded: Vec<SignedSidechainBlock> =
			Decode::decode(&mut fetched_blocks_encoded.as_slice()).unwrap();

		assert_eq!(blocks, fetched_blocks_decoded);
	}

	fn setup_sidechain_ocall_with_peer_blocks(
		peer_blocks_map: HashMap<ShardIdentifier, Vec<SignedSidechainBlock>>,
	) -> TestSidechainOCall {
		let block_broadcaster_mock = Arc::new(BroadcastBlocksMock {});
		let block_storage_mock = Arc::new(BlockStorageMock {});
		let peer_updater_mock = Arc::new(UpdateWorkerPeersMock {});
		let peer_block_fetcher_mock = Arc::new(
			FetchBlocksFromPeerMock::<SignedSidechainBlock>::default()
				.with_signed_blocks(peer_blocks_map),
		);
		let scoped_tokio_handle = Arc::new(ScopedTokioHandle::default());

		SidechainOCall::new(
			block_broadcaster_mock,
			block_storage_mock,
			peer_updater_mock,
			peer_block_fetcher_mock,
			scoped_tokio_handle,
		)
	}
}
