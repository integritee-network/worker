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
use itc_parentchain_block_importer::ImportParentchainBlocks;
use itp_block_import_queue::{PeekBlockQueue, PopFromBlockQueue, PushToBlockQueue};
use log::debug;
use std::vec::Vec;

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
	fn import_until(
		&self,
		predicate: impl Fn(&SignedBlockType) -> bool,
	) -> Result<Option<SignedBlockType>>;

	/// Search the import queue with a given predicate and return a reference
	/// to the first element that matches the predicate.
	fn peek(&self, predicate: impl Fn(&SignedBlockType) -> bool)
		-> Result<Option<SignedBlockType>>;

	/// Peek the latest block in the import queue. Returns None if queue is empty.
	fn peek_latest(&self) -> Result<Option<SignedBlockType>>;
}

/// Dispatcher for block imports that retains blocks until the import is triggered, using the
/// `TriggerParentchainBlockImport` trait implementation.
pub struct TriggeredDispatcher<BlockImporter, BlockImportQueue> {
	block_importer: BlockImporter,
	import_queue: BlockImportQueue,
}

impl<BlockImporter, BlockImportQueue> TriggeredDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	pub fn new(block_importer: BlockImporter, block_import_queue: BlockImportQueue) -> Self {
		TriggeredDispatcher { block_importer, import_queue: block_import_queue }
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
		debug!("Pushing parentchain block(s) ({}) to import queue", blocks.len());
		// Push all the blocks to be dispatched into the queue.
		self.import_queue.push_multiple(blocks).map_err(Error::BlockImportQueue)
	}
}

impl<BlockImporter, BlockImportQueue> TriggerParentchainBlockImport<BlockImporter::SignedBlockType>
	for TriggeredDispatcher<BlockImporter, BlockImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToBlockQueue<BlockImporter::SignedBlockType>
		+ PopFromBlockQueue<BlockType = BlockImporter::SignedBlockType>
		+ PeekBlockQueue<BlockType = BlockImporter::SignedBlockType>,
{
	fn import_all(&self) -> Result<Option<BlockImporter::SignedBlockType>> {
		let blocks_to_import = self.import_queue.pop_all().map_err(Error::BlockImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		debug!("Trigger import of all parentchain blocks in queue ({})", blocks_to_import.len());

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
	}

	fn import_all_but_latest(&self) -> Result<()> {
		let blocks_to_import =
			self.import_queue.pop_all_but_last().map_err(Error::BlockImportQueue)?;

		debug!(
			"Trigger import of all parentchain blocks, except the latest, from queue ({})",
			blocks_to_import.len()
		);

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)
	}

	fn import_until(
		&self,
		predicate: impl Fn(&BlockImporter::SignedBlockType) -> bool,
	) -> Result<Option<BlockImporter::SignedBlockType>> {
		let blocks_to_import =
			self.import_queue.pop_until(predicate).map_err(Error::BlockImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		debug!(
			"Import of parentchain blocks has been triggered, importing {} blocks from queue",
			blocks_to_import.len()
		);

		self.block_importer
			.import_parentchain_blocks(blocks_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
	}

	fn peek(
		&self,
		predicate: impl Fn(&BlockImporter::SignedBlockType) -> bool,
	) -> Result<Option<BlockImporter::SignedBlockType>> {
		debug!(
			"Peek find parentchain import queue (currently has {} elements)",
			self.import_queue.peek_queue_size().unwrap_or(0)
		);
		self.import_queue.peek_find(predicate).map_err(Error::BlockImportQueue)
	}

	fn peek_latest(&self) -> Result<Option<BlockImporter::SignedBlockType>> {
		debug!(
			"Peek latest parentchain import queue (currently has {} elements)",
			self.import_queue.peek_queue_size().unwrap_or(0)
		);
		self.import_queue.peek_last().map_err(Error::BlockImportQueue)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itc_parentchain_block_importer::block_importer_mock::ParentchainBlockImporterMock;
	use itp_block_import_queue::{BlockImportQueue, PopFromBlockQueue};

	type SignedBlockType = u32;
	type TestBlockImporter = ParentchainBlockImporterMock<SignedBlockType>;
	type TestQueue = BlockImportQueue<SignedBlockType>;
	type TestDispatcher = TriggeredDispatcher<TestBlockImporter, TestQueue>;

	#[test]
	fn dispatching_blocks_imports_none_if_not_triggered() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();

		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
	}

	#[test]
	fn dispatching_blocks_multiple_times_add_all_to_queue() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.dispatch_import(vec![6, 7, 8]).unwrap();

		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
	}

	#[test]
	fn triggering_import_all_empties_queue() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let latest_imported = dispatcher.import_all().unwrap().unwrap();

		assert_eq!(latest_imported, 5);
		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4, 5]);
		assert!(dispatcher.import_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_all_on_empty_queue_imports_none() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![]).unwrap();
		let maybe_latest_imported = dispatcher.import_all().unwrap();

		assert!(maybe_latest_imported.is_none());
		assert_eq!(
			dispatcher.block_importer.get_all_imported_blocks(),
			Vec::<SignedBlockType>::default()
		);
		assert!(dispatcher.import_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_until_leaves_remaining_in_queue() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let latest_imported =
			dispatcher.import_until(|i: &SignedBlockType| i == &4).unwrap().unwrap();

		assert_eq!(latest_imported, 4);
		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![5]);
	}

	#[test]
	fn triggering_import_until_with_no_match_imports_nothing() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		let maybe_latest_imported = dispatcher.import_until(|i: &SignedBlockType| i == &8).unwrap();

		assert!(maybe_latest_imported.is_none());
		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
	}

	#[test]
	fn trigger_import_all_but_latest_works() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5]).unwrap();
		dispatcher.import_all_but_latest().unwrap();

		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![5]);
	}

	fn test_fixtures() -> TestDispatcher {
		let import_queue = BlockImportQueue::<SignedBlockType>::default();
		let block_importer = ParentchainBlockImporterMock::<SignedBlockType>::default();
		let dispatcher = TriggeredDispatcher::new(block_importer, import_queue);
		dispatcher
	}
}
