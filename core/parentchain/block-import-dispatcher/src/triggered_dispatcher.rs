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
use itp_import_queue::{PeekQueue, PopFromQueue, PushToQueue};
use log::trace;
use std::vec::Vec;

pub type RawEventsPerBlock = Vec<u8>;

/// Trait to specifically trigger the import of parentchain blocks.
pub trait TriggerParentchainBlockImport {
	type SignedBlockType;
	/// Trigger the import of all queued block, **including** the latest one.
	///
	/// Returns the latest imported block (if any).
	fn import_all(&self) -> Result<Option<Self::SignedBlockType>>;

	/// Trigger import of all queued blocks, **except** the latest one.
	fn import_all_but_latest(&self) -> Result<()>;

	/// Trigger import of all blocks up to **and including** a specific block.
	///
	/// If no block in the queue matches, then no blocks will be imported.
	/// Returns the latest imported block (if any).
	fn import_until(
		&self,
		predicate: impl Fn(&Self::SignedBlockType) -> bool,
	) -> Result<Option<Self::SignedBlockType>>;

	/// Search the import queue with a given predicate and return a reference
	/// to the first element that matches the predicate.
	fn peek(
		&self,
		predicate: impl Fn(&Self::SignedBlockType) -> bool,
	) -> Result<Option<Self::SignedBlockType>>;

	/// Peek the latest block in the import queue. Returns None if queue is empty.
	fn peek_latest(&self) -> Result<Option<Self::SignedBlockType>>;
}

/// Dispatcher for block imports that retains blocks until the import is triggered, using the
/// `TriggerParentchainBlockImport` trait implementation.
pub struct TriggeredDispatcher<BlockImporter, BlockImportQueue, EventsImportQueue> {
	block_importer: BlockImporter,
	import_queue: BlockImportQueue,
	events_queue: EventsImportQueue,
}

impl<BlockImporter, BlockImportQueue, EventsImportQueue>
	TriggeredDispatcher<BlockImporter, BlockImportQueue, EventsImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToQueue<BlockImporter::SignedBlockType>
		+ PopFromQueue<ItemType = BlockImporter::SignedBlockType>,
	EventsImportQueue: PushToQueue<RawEventsPerBlock> + PopFromQueue<ItemType = RawEventsPerBlock>,
{
	pub fn new(
		block_importer: BlockImporter,
		block_import_queue: BlockImportQueue,
		events_import_queue: EventsImportQueue,
	) -> Self {
		TriggeredDispatcher {
			block_importer,
			import_queue: block_import_queue,
			events_queue: events_import_queue,
		}
	}
}

impl<BlockImporter, BlockImportQueue, SignedBlockType, EventsImportQueue>
	DispatchBlockImport<SignedBlockType>
	for TriggeredDispatcher<BlockImporter, BlockImportQueue, EventsImportQueue>
where
	BlockImporter: ImportParentchainBlocks<SignedBlockType = SignedBlockType>,
	BlockImportQueue: PushToQueue<SignedBlockType> + PopFromQueue<ItemType = SignedBlockType>,
	EventsImportQueue: PushToQueue<RawEventsPerBlock> + PopFromQueue<ItemType = RawEventsPerBlock>,
{
	fn dispatch_import(
		&self,
		blocks: Vec<SignedBlockType>,
		events: Vec<RawEventsPerBlock>,
	) -> Result<()> {
		trace!(
			"Pushing parentchain block(s) and event(s) ({}) ({}) to import queue",
			blocks.len(),
			events.len()
		);
		// Push all the blocks to be dispatched into the queue.
		self.events_queue.push_multiple(events).map_err(Error::ImportQueue)?;
		self.import_queue.push_multiple(blocks).map_err(Error::ImportQueue)
	}
}

impl<BlockImporter, BlockImportQueue, EventsImportQueue> TriggerParentchainBlockImport
	for TriggeredDispatcher<BlockImporter, BlockImportQueue, EventsImportQueue>
where
	BlockImporter: ImportParentchainBlocks,
	BlockImportQueue: PushToQueue<BlockImporter::SignedBlockType>
		+ PopFromQueue<ItemType = BlockImporter::SignedBlockType>
		+ PeekQueue<ItemType = BlockImporter::SignedBlockType>,
	EventsImportQueue: PushToQueue<RawEventsPerBlock>
		+ PopFromQueue<ItemType = RawEventsPerBlock>
		+ PeekQueue<ItemType = RawEventsPerBlock>,
{
	type SignedBlockType = BlockImporter::SignedBlockType;

	fn import_all(&self) -> Result<Option<BlockImporter::SignedBlockType>> {
		let blocks_to_import = self.import_queue.pop_all().map_err(Error::ImportQueue)?;
		let events_to_import = self.events_queue.pop_all().map_err(Error::ImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		trace!(
			"Trigger import of all parentchain blocks and events in queue ({}) ({})",
			blocks_to_import.len(),
			events_to_import.len()
		);

		self.block_importer
			.import_parentchain_blocks(blocks_to_import, events_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
	}

	fn import_all_but_latest(&self) -> Result<()> {
		let blocks_to_import = self.import_queue.pop_all_but_last().map_err(Error::ImportQueue)?;
		let events_to_import = self.events_queue.pop_all_but_last().map_err(Error::ImportQueue)?;

		trace!(
			"Trigger import of all parentchain blocks and events, except the latest, from queue ({}) ({})",
			blocks_to_import.len(),
			events_to_import.len()
		);

		self.block_importer
			.import_parentchain_blocks(blocks_to_import, events_to_import)
			.map_err(Error::BlockImport)
	}

	fn import_until(
		&self,
		predicate: impl Fn(&BlockImporter::SignedBlockType) -> bool,
	) -> Result<Option<BlockImporter::SignedBlockType>> {
		let blocks_to_import =
			self.import_queue.pop_until(predicate).map_err(Error::ImportQueue)?;

		let events_to_import = self
			.events_queue
			.pop_from_front_until(blocks_to_import.len())
			.map_err(Error::ImportQueue)?;

		let latest_imported_block = blocks_to_import.last().map(|b| (*b).clone());

		trace!(
			"Import of parentchain blocks and events has been triggered, importing {} blocks and {} events from queue",
			blocks_to_import.len(),
			events_to_import.len(),
		);

		self.block_importer
			.import_parentchain_blocks(blocks_to_import, events_to_import)
			.map_err(Error::BlockImport)?;

		Ok(latest_imported_block)
	}

	fn peek(
		&self,
		predicate: impl Fn(&BlockImporter::SignedBlockType) -> bool,
	) -> Result<Option<BlockImporter::SignedBlockType>> {
		trace!(
			"Peek find parentchain import queue (currently has {} elements)",
			self.import_queue.peek_queue_size().unwrap_or(0)
		);
		self.import_queue.peek_find(predicate).map_err(Error::ImportQueue)
	}

	fn peek_latest(&self) -> Result<Option<BlockImporter::SignedBlockType>> {
		trace!(
			"Peek latest parentchain import queue (currently has {} elements)",
			self.import_queue.peek_queue_size().unwrap_or(0)
		);
		self.import_queue.peek_last().map_err(Error::ImportQueue)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itc_parentchain_block_importer::block_importer_mock::ParentchainBlockImporterMock;
	use itp_import_queue::{ImportQueue, PopFromQueue};

	type SignedBlockType = u32;
	type TestBlockImporter = ParentchainBlockImporterMock<SignedBlockType>;
	type TestQueue = ImportQueue<SignedBlockType>;
	type TestEventsQueue = ImportQueue<RawEventsPerBlock>;
	type TestDispatcher = TriggeredDispatcher<TestBlockImporter, TestQueue, TestEventsQueue>;

	#[test]
	fn dispatching_blocks_imports_none_if_not_triggered() {
		let dispatcher = test_fixtures();

		dispatcher
			.dispatch_import(vec![1, 2, 3, 4, 5], vec![vec![1], vec![2], vec![3], vec![4], vec![5]])
			.unwrap();

		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
		assert_eq!(
			dispatcher.events_queue.pop_all().unwrap(),
			vec![vec![1], vec![2], vec![3], vec![4], vec![5]]
		);
	}

	#[test]
	fn dispatching_blocks_multiple_times_add_all_to_queue() {
		let dispatcher = test_fixtures();

		dispatcher
			.dispatch_import(vec![1, 2, 3, 4, 5], vec![vec![1], vec![2], vec![3], vec![4], vec![5]])
			.unwrap();
		dispatcher
			.dispatch_import(vec![6, 7, 8], vec![vec![6], vec![7], vec![8]])
			.unwrap();

		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
		assert_eq!(
			dispatcher.events_queue.pop_all().unwrap(),
			vec![vec![1], vec![2], vec![3], vec![4], vec![5], vec![6], vec![7], vec![8]]
		);
	}

	#[test]
	fn triggering_import_all_empties_queue() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5], vec![]).unwrap();
		let latest_imported = dispatcher.import_all().unwrap().unwrap();

		assert_eq!(latest_imported, 5);
		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4, 5]);
		assert!(dispatcher.import_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_all_on_empty_queue_imports_none() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![], vec![]).unwrap();
		let maybe_latest_imported = dispatcher.import_all().unwrap();

		assert!(maybe_latest_imported.is_none());
		assert_eq!(
			dispatcher.block_importer.get_all_imported_blocks(),
			Vec::<SignedBlockType>::default()
		);
		assert!(dispatcher.import_queue.is_empty().unwrap());
		assert!(dispatcher.events_queue.is_empty().unwrap());
	}

	#[test]
	fn triggering_import_until_leaves_remaining_in_queue() {
		let dispatcher = test_fixtures();

		dispatcher
			.dispatch_import(vec![1, 2, 3, 4, 5], vec![vec![1], vec![2], vec![3], vec![4], vec![5]])
			.unwrap();
		let latest_imported =
			dispatcher.import_until(|i: &SignedBlockType| i == &4).unwrap().unwrap();

		assert_eq!(latest_imported, 4);
		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![5]);
		assert_eq!(dispatcher.events_queue.pop_all().unwrap(), vec![vec![5]]);
	}

	#[test]
	fn triggering_import_until_with_no_match_imports_nothing() {
		let dispatcher = test_fixtures();

		dispatcher
			.dispatch_import(vec![1, 2, 3, 4, 5], vec![vec![1], vec![2], vec![3], vec![4], vec![5]])
			.unwrap();
		let maybe_latest_imported = dispatcher.import_until(|i: &SignedBlockType| i == &8).unwrap();

		assert!(maybe_latest_imported.is_none());
		assert!(dispatcher.block_importer.get_all_imported_blocks().is_empty());
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![1, 2, 3, 4, 5]);
		assert_eq!(
			dispatcher.events_queue.pop_all().unwrap(),
			vec![vec![1], vec![2], vec![3], vec![4], vec![5]]
		);
	}

	#[test]
	fn trigger_import_all_but_latest_works() {
		let dispatcher = test_fixtures();

		dispatcher.dispatch_import(vec![1, 2, 3, 4, 5], vec![]).unwrap();
		dispatcher.import_all_but_latest().unwrap();

		assert_eq!(dispatcher.block_importer.get_all_imported_blocks(), vec![1, 2, 3, 4]);
		assert_eq!(dispatcher.import_queue.pop_all().unwrap(), vec![5]);
	}

	fn test_fixtures() -> TestDispatcher {
		let events_import_queue = ImportQueue::<RawEventsPerBlock>::default();
		let import_queue = ImportQueue::<SignedBlockType>::default();
		let block_importer = ParentchainBlockImporterMock::<SignedBlockType>::default();
		let dispatcher =
			TriggeredDispatcher::new(block_importer, import_queue, events_import_queue);
		dispatcher
	}
}
