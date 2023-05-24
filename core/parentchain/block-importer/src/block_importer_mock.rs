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

//! Block importer mock.

use crate::{
	error::{Error, Result},
	ImportParentchainBlocks,
};
use std::{sync::RwLock, vec::Vec};

/// Mock implementation for the block importer.
///
/// Just stores all the blocks that were sent to import internally.
#[derive(Default)]
pub struct ParentchainBlockImporterMock<SignedBlockT> {
	imported_blocks: RwLock<Vec<SignedBlockT>>,
}

impl<SignedBlockT> ParentchainBlockImporterMock<SignedBlockT>
where
	SignedBlockT: Clone,
{
	pub fn get_all_imported_blocks(&self) -> Vec<SignedBlockT> {
		let imported_blocks_lock = self.imported_blocks.read().unwrap();
		(*imported_blocks_lock).clone()
	}
}

impl<SignedBlockT> ImportParentchainBlocks for ParentchainBlockImporterMock<SignedBlockT>
where
	SignedBlockT: Clone,
{
	type SignedBlockType = SignedBlockT;

	fn import_parentchain_blocks(
		&self,
		blocks_to_import: Vec<Self::SignedBlockType>,
		_events: Vec<Vec<u8>>,
	) -> Result<()> {
		let mut imported_blocks_lock = self.imported_blocks.write().map_err(|e| {
			Error::Other(format!("failed to acquire lock for imported blocks vec: {:?}", e).into())
		})?;
		imported_blocks_lock.extend(blocks_to_import);
		Ok(())
	}
}
