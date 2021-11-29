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

//! A block import dispatcher that retains the latest block until its import is explicitly triggered.

use crate::{
	error::{Error, Result},
	DispatchBlockImport,
};
use itc_parentchain_block_import_queue::{PopFromBlockQueue, PushToBlockQueue};
use itc_parentchain_block_importer::ImportParentchainBlocks;
use std::{sync::Arc, vec::Vec};

/// Trait to specifically trigger the import of the latest retained parentchain block.
pub trait TriggerLatestParentchainBlockImport {
	fn import_latest(&self) -> Result<()>;
}

/// Dispatcher for block imports that always retains the latest parentchain block.
/// Importing the latest block has to be triggered specifically.
///
/// Uses a queue internally. Upon receiving a dispatch request, it imports all blocks in the queue
/// except the latest one.
pub struct RetainLatestDispatcher<BlockImporter, BlockImportQueue> {
	block_importer: Arc<BlockImporter>,
	block_import_queue: Arc<BlockImportQueue>,
}

impl<BlockImporter, BlockImportQueue> RetainLatestDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockType = BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	pub fn new(
		block_importer: Arc<BlockImporter>,
		block_import_queue: Arc<BlockImportQueue>,
	) -> Self {
		RetainLatestDispatcher { block_importer, block_import_queue }
	}
}

impl<BlockImporter, BlockImportQueue> DispatchBlockImport
	for RetainLatestDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockType = BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	type SignedBlockType = BlockImporter::SignedBlockType;

	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()> {
		// Push all the blocks to be dispatched into the queue.
		self.block_import_queue.push_multiple(blocks).map_err(Error::BlockImportQueue)?;

		// And pop all but the last block from the queue and import them.
		let blocks_to_import =
			self.block_import_queue.pop_all_but_last().map_err(Error::BlockImportQueue)?;

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(|e| e.into())
	}
}

impl<BlockImporter, BlockImportQueue> TriggerLatestParentchainBlockImport
	for RetainLatestDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockType = BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	fn import_latest(&self) -> Result<()> {
		// With this trigger, we import all blocks from the queue, including the latest one.
		let blocks_to_import =
			self.block_import_queue.pop_all().map_err(Error::BlockImportQueue)?;

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(|e| e.into())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itc_parentchain_block_import_queue::BlockImportQueue;
	use itc_parentchain_block_importer::block_importer_mock::ParentchainBlockImporterMock;

	type SignedBlockType = u32;
	type TestBlockImporter = ParentchainBlockImporterMock<SignedBlockType>;
	type TestQueue = BlockImportQueue<SignedBlockType>;
	type TestDispatcher = RetainLatestDispatcher<TestBlockImporter, TestQueue>;

	#[test]
	fn dispatching_blocks_imports_all_but_latest() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();

		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert!(!import_queue.is_empty().unwrap());
	}

	#[test]
	fn dispatching_blocks_multiple_times_imports_all_but_very_last() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.dispatch_import(vec![6, 7, 8]).unwrap();

		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4, 5, 6, 7]);
		assert_eq!(import_queue.pop_all().unwrap(), vec![8]);
	}

	#[test]
	fn triggering_import_of_latest_imports_all_remaining_blocks_in_queue() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.import_latest().unwrap();

		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4, 5]);
		assert!(import_queue.is_empty().unwrap());
	}

	fn test_fixtures() -> (TestDispatcher, Arc<TestBlockImporter>, Arc<TestQueue>) {
		let import_queue = Arc::new(BlockImportQueue::<SignedBlockType>::default());
		let block_importer = Arc::new(ParentchainBlockImporterMock::<SignedBlockType>::default());
		let dispatcher = RetainLatestDispatcher::new(block_importer.clone(), import_queue.clone());
		(dispatcher, block_importer, import_queue)
	}
}
