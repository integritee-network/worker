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

use crate::{Result, SyncBlockFromPeer};
use core::marker::PhantomData;
use itertools::Itertools;
use itp_import_queue::{PeekQueue, PopFromQueue};
use itp_types::SidechainBlockNumber;
use its_primitives::traits::{
	Block as BlockTrait, Header, SignedBlock as SignedSidechainBlockTrait,
};
use log::{debug, trace};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{sync::Arc, time::Instant, vec::Vec};

/// Trait to trigger working the sidechain block import queue.
pub trait ProcessBlockImportQueue<ParentchainBlockHeader> {
	/// Pop sidechain blocks from the import queue and import them until queue is empty.
	fn process_queue(
		&self,
		current_parentchain_header: &ParentchainBlockHeader,
	) -> Result<ParentchainBlockHeader>;
}

pub struct BlockImportQueueWorker<
	ParentchainBlock,
	SignedSidechainBlock,
	BlockImportQueue,
	PeerBlockSyncer,
> {
	block_import_queue: Arc<BlockImportQueue>,
	peer_block_syncer: Arc<PeerBlockSyncer>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
	BlockImportQueueWorker<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	SignedSidechainBlock::Block: BlockTrait,
	BlockImportQueue: PopFromQueue<ItemType = SignedSidechainBlock> + PeekQueue,
	PeerBlockSyncer: SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>,
{
	pub fn new(
		block_import_queue: Arc<BlockImportQueue>,
		peer_block_syncer: Arc<PeerBlockSyncer>,
	) -> Self {
		BlockImportQueueWorker {
			block_import_queue,
			peer_block_syncer,
			_phantom: Default::default(),
		}
	}

	fn record_timings(start_time: Instant, number_of_imported_blocks: usize) {
		let elapsed_time_millis = start_time.elapsed().as_millis();
		let time_millis_per_block =
			(elapsed_time_millis as f64 / number_of_imported_blocks as f64).ceil();
		debug!(
			"Imported {} blocks in {} ms (average of {} ms per block)",
			number_of_imported_blocks, elapsed_time_millis, time_millis_per_block
		);
	}
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImportQueue, PeerBlockSyncer>
	ProcessBlockImportQueue<ParentchainBlock::Header>
	for BlockImportQueueWorker<
		ParentchainBlock,
		SignedSidechainBlock,
		BlockImportQueue,
		PeerBlockSyncer,
	> where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	SignedSidechainBlock::Block: BlockTrait,
	BlockImportQueue: PopFromQueue<ItemType = SignedSidechainBlock> + PeekQueue,
	PeerBlockSyncer: SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>,
{
	fn process_queue(
		&self,
		current_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header> {
		let mut latest_imported_parentchain_header = current_parentchain_header.clone();
		let mut number_of_imported_blocks = 0usize;
		let start_time = Instant::now();

		trace!(
			"processing import queue with {:?} sidechain blocks",
			self.block_import_queue.peek_queue_size()
		);

		if let Ok(candidates) = self.block_import_queue.pop_all() {
			let mut sorted_candidates = candidates
				.iter()
				.map(|b| (b.block().header().block_number(), b))
				.collect::<Vec<(SidechainBlockNumber, &SignedSidechainBlock)>>();
			sorted_candidates.sort_by(|a, b| a.0.cmp(&b.0));
			number_of_imported_blocks = sorted_candidates
				.iter()
				.group_by(|&a| a.0)
				.into_iter()
				.filter_map(|(block_number, competitors)| {
					let mut competitors: Vec<&SignedSidechainBlock> =
						competitors.map(|&c| c.1).collect();
					// deterministic import order decreases chances for forks
					competitors.sort_by(|a, b| a.block().hash().cmp(&b.block().hash()));
					trace!("nr of competitors for block {}: {}", block_number, competitors.len());
					let mut winner = None;
					for block in competitors {
						if let Ok(parentchain_header) = self.peer_block_syncer.import_or_sync_block(
							block.clone(),
							&latest_imported_parentchain_header,
						) {
							latest_imported_parentchain_header = parentchain_header;
							winner = Some(block);
							break
						};
					}
					winner
				})
				.count();
		}
		Self::record_timings(start_time, number_of_imported_blocks);
		Ok(latest_imported_parentchain_header)
	}
}
