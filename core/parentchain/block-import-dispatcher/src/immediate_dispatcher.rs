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
use std::{sync::Arc, vec::Vec};

/// Block import dispatcher that immediately imports the blocks, without any processing or queueing.
pub struct ImmediateDispatcher<BlockImporter> {
	block_importer: Arc<BlockImporter>,
}

impl<BlockImporter> ImmediateDispatcher<BlockImporter> {
	pub fn new(block_importer: Arc<BlockImporter>) -> Self {
		ImmediateDispatcher { block_importer }
	}
}

impl<BlockImporter> DispatchBlockImport for ImmediateDispatcher<BlockImporter>
where
	BlockImporter: ImportParentchainBlocks,
{
	type SignedBlockType = BlockImporter::SignedBlockType;

	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()> {
		self.block_importer.import_parentchain_blocks(blocks).map_err(|e| e.into())
	}
}
