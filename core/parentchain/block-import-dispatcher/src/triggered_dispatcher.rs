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

//! A block import dispatcher that retains all blocks in a queue until import is triggered.

use crate::{
	error::{Error, Result},
	DispatchBlockImport,
};
use itc_parentchain_block_import_queue::{PopFromBlockQueue, PushToBlockQueue};
use itc_parentchain_block_importer::ImportParentchainBlocks;
use std::{sync::Arc, vec::Vec};

/// Trait to specifically trigger the import of parentchain blocks.
pub trait TriggerParentchainBlockImport<SignedBlockType> {
	/// Trigger the import of all queued block, **including** the latest one.
	///
	/// Returns the latest imported block (if any).
	fn import_all(&self) -> Result<Option<SignedBlockType>>;

	/// Trigger import of all queued blocks, **except** the latest one.
	fn import_all_but_latest(&self) -> Result<()>;

	/// Trigger import of all blocks up to **and including** a specific block.
	///
	/// If no block in the queue matches, then no blocks will be imported.
	/// Returns the latest imported block (if any).
	fn import_until<MatchingF>(&self, matching_func: MatchingF) -> Result<Option<SignedBlockType>>
	where
		MatchingF: Fn(&SignedBlockType) -> bool;
}

/// Dispatcher for block imports that retains blocks until the import is triggered, using the
/// `TriggerParentchainBlockImport` trait implementation.
pub struct TriggeredDispatcher<BlockImporter, BlockImportQueue> {
	block_importer: Arc<BlockImporter>,
	block_import_queue: Arc<BlockImportQueue>,
}

impl<BlockImporter, BlockImportQueue> TriggeredDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	pub fn new(
		block_importer: Arc<BlockImporter>,
		block_import_queue: Arc<BlockImportQueue>,
	) -> Self {
		TriggeredDispatcher { block_importer, block_import_queue }
	}
}

impl<BlockImporter, BlockImportQueue> DispatchBlockImport
	for TriggeredDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	type SignedBlockType = BlockImporter::SignedBlockType;

	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()> {
		// Push all the blocks to be dispatched into the queue.
		self.block_import_queue.push_multiple(blocks).map_err(Error::BlockImportQueue)
	}
}

impl<BlockImporter, BlockImportQueue> TriggerParentchainBlockImport<BlockImporter::SignedBlockType>
	for TriggeredDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	fn import_all(&self) -> Result<Option<BlockImporter::SignedBlockType>> {
		let blocks_to_import =
			self.block_import_queue.pop_all().map_err(Error::BlockImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
	}

	fn import_all_but_latest(&self) -> Result<()> {
		let blocks_to_import =
			self.block_import_queue.pop_all_but_last().map_err(Error::BlockImportQueue)?;

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)
	}

	fn import_until<MatchingF>(
		&self,
		matching_func: MatchingF,
	) -> Result<Option<BlockImporter::SignedBlockType>>
	where
		MatchingF: Fn(&BlockImporter::SignedBlockType) -> bool,
	{
		let blocks_to_import = self
			.block_import_queue
			.pop_until(matching_func)
			.map_err(Error::BlockImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
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
	type TestDispatcher = TriggeredDispatcher<TestBlockImporter, TestQueue>;

	#[test]
	fn dispatching_blocks_imports_none_if_not_triggered() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();

		assert!(block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
	}

	#[test]
	fn dispatching_blocks_multiple_times_add_all_to_queue() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.dispatch_import(vec![6, 7, 8]).unwrap();

		assert!(block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
	}

	#[test]
	fn triggering_import_all_empties_queue() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let latest_imported = dispatcher.import_all().unwrap().unwrap();

		assert_eq!(latest_imported, 5);
		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4, 5]);
		assert!(import_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_all_on_empty_queue_imports_none() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![]).unwrap();
		let maybe_latest_imported = dispatcher.import_all().unwrap();

		assert!(maybe_latest_imported.is_none());
		assert_eq!(block_importer.get_all_imported_blocks(), Vec::<SignedBlockType>::default());
		assert!(import_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_until_leaves_remaining_in_queue() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let latest_imported =
			dispatcher.import_until(|i: &SignedBlockType| i == &4).unwrap().unwrap();

		assert_eq!(latest_imported, 4);
		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(import_queue.pop_all().unwrap(), vec![5]);
	}

	#[test]
	fn triggering_import_until_with_no_match_imports_nothing() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let maybe_latest_imported = dispatcher.import_until(|i: &SignedBlockType| i == &8).unwrap();

		assert!(maybe_latest_imported.is_none());
		assert!(block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
	}

	#[test]
	fn trigger_import_all_but_latest_works() {
		let (dispatcher, block_importer, import_queue) = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.import_all_but_latest().unwrap();

		assert_eq!(block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(import_queue.pop_all().unwrap(), vec![5]);
	}

	fn test_fixtures() -> (TestDispatcher, Arc<TestBlockImporter>, Arc<TestQueue>) {
		let import_queue = Arc::new(BlockImportQueue::<SignedBlockType>::default());
		let block_importer = Arc::new(ParentchainBlockImporterMock::<SignedBlockType>::default());
		let dispatcher = TriggeredDispatcher::new(block_importer.clone(), import_queue.clone());
		(dispatcher, block_importer, import_queue)
	}
}
