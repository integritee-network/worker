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

use crate::{error::Result, DispatchBlockImport};
use itc_parentchain_block_importer::ImportParentchainBlocks;
use log::*;
use std::{boxed::Box, vec::Vec};

/// Block import dispatcher that immediately imports the blocks, without any processing or queueing.
pub struct ImmediateDispatcher<BlockImporter> {
	block_importer: BlockImporter,
	import_event_observers: Vec<Box<dyn Fn() + Send + Sync + 'static>>,
}

impl<BlockImporter> ImmediateDispatcher<BlockImporter> {
	pub fn new(block_importer: BlockImporter) -> Self {
		ImmediateDispatcher { block_importer, import_event_observers: Vec::new() }
	}

	pub fn with_observer<F>(self, callback: F) -> Self
	where
		F: Fn() + Send + Sync + 'static,
	{
		let mut updated_observers = self.import_event_observers;
		updated_observers.push(Box::new(callback));

		Self { block_importer: self.block_importer, import_event_observers: updated_observers }
	}
}

impl<BlockImporter, SignedBlockType> DispatchBlockImport<SignedBlockType>
	for ImmediateDispatcher<BlockImporter>
where
	BlockImporter: ImportParentchainBlocks<SignedBlockType = SignedBlockType>,
{
	fn dispatch_import(&self, blocks: Vec<SignedBlockType>, events: Vec<Vec<u8>>) -> Result<()> {
		debug!("Importing {} parentchain blocks", blocks.len());
		self.block_importer.import_parentchain_blocks(blocks, events)?;
		debug!("Notifying {} observers of import", self.import_event_observers.len());
		self.import_event_observers.iter().for_each(|callback| callback());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itc_parentchain_block_importer::block_importer_mock::ParentchainBlockImporterMock;
	use std::{
		sync::{Arc, RwLock},
		vec,
	};

	type SignedBlockType = u32;
	type TestBlockImporter = ParentchainBlockImporterMock<SignedBlockType>;
	type TestDispatcher = ImmediateDispatcher<TestBlockImporter>;

	#[derive(Default)]
	struct NotificationCounter {
		counter: RwLock<usize>,
	}

	impl NotificationCounter {
		fn increment(&self) {
			*self.counter.write().unwrap() += 1;
		}

		pub fn get_counter(&self) -> usize {
			*self.counter.read().unwrap()
		}
	}

	#[test]
	fn listeners_get_notified_upon_import() {
		let block_importer = TestBlockImporter::default();
		let notification_counter = Arc::new(NotificationCounter::default());
		let counter_clone = notification_counter.clone();
		let dispatcher = TestDispatcher::new(block_importer).with_observer(move || {
			counter_clone.increment();
		});

		dispatcher.dispatch_import(vec![1u32, 2u32], vec![]).unwrap();

		assert_eq!(1, notification_counter.get_counter());
	}
}
