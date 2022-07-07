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

use crate::{error::Result, import_event_listener::ListenToImportEvent, DispatchBlockImport};
use itc_parentchain_block_importer::ImportParentchainBlocks;
use std::{boxed::Box, sync::Arc, vec::Vec};

/// Block import dispatcher that immediately imports the blocks, without any processing or queueing.
pub struct ImmediateDispatcher<BlockImporter> {
	block_importer: Arc<BlockImporter>,
	import_event_listeners: Vec<Arc<Box<dyn ListenToImportEvent>>>,
}

impl<BlockImporter> ImmediateDispatcher<BlockImporter> {
	pub fn new(block_importer: Arc<BlockImporter>) -> Self {
		ImmediateDispatcher { block_importer, import_event_listeners: Vec::new() }
	}

	pub fn with_listeners(
		block_importer: Arc<BlockImporter>,
		import_event_listeners: Vec<Arc<Box<dyn ListenToImportEvent>>>,
	) -> Self {
		ImmediateDispatcher { block_importer, import_event_listeners }
	}
}

impl<BlockImporter> DispatchBlockImport for ImmediateDispatcher<BlockImporter>
where
	BlockImporter: ImportParentchainBlocks,
{
	type SignedBlockType = BlockImporter::SignedBlockType;

	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()> {
		self.block_importer.import_parentchain_blocks(blocks)?;
		self.import_event_listeners.iter().for_each(|l| l.notify());
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::import_event_listener::mock::{ListenToImportEventMock, NotificationCounter};
	use itc_parentchain_block_importer::block_importer_mock::ParentchainBlockImporterMock;
	use std::vec;

	type SignedBlockType = u32;
	type TestBlockImporter = ParentchainBlockImporterMock<SignedBlockType>;
	type TestDispatcher = ImmediateDispatcher<TestBlockImporter>;

	#[test]
	fn listeners_get_notified_upon_import() {
		let block_importer = Arc::new(TestBlockImporter::default());
		let notification_counter = Arc::new(NotificationCounter::default());
		let listener: Arc<Box<dyn ListenToImportEvent>> =
			Arc::new(Box::new(ListenToImportEventMock::new(notification_counter.clone())));
		let dispatcher = TestDispatcher::with_listeners(block_importer, vec![listener.clone()]);

		dispatcher.dispatch_import(vec![1u32, 2u32]).unwrap();

		assert_eq!(1, notification_counter.get_counter());
	}
}
