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

use crate::{Error, Result, SyncBlockFromPeer};
use core::marker::PhantomData;
use itp_block_import_queue::PopFromBlockQueue;
use its_primitives::traits::{Block as BlockTrait, SignedBlock as SignedSidechainBlockTrait};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::sync::Arc;

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
	BlockImportQueue: PopFromBlockQueue<BlockType = SignedSidechainBlock>,
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
	BlockImportQueue: PopFromBlockQueue<BlockType = SignedSidechainBlock>,
	PeerBlockSyncer: SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>,
{
	fn process_queue(
		&self,
		current_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header> {
		let mut latest_imported_parentchain_header = current_parentchain_header.clone();

		loop {
			match self.block_import_queue.pop_front() {
				Ok(maybe_block) => match maybe_block {
					Some(block) => {
						latest_imported_parentchain_header = self
							.peer_block_syncer
							.sync_block(block, &latest_imported_parentchain_header)?;
					},
					None => return Ok(latest_imported_parentchain_header),
				},
				Err(e) => return Err(Error::FailedToPopBlockImportQueue(e)),
			}
		}
	}
}
