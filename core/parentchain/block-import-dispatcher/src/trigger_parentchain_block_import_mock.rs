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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{error::Result, triggered_dispatcher::TriggerParentchainBlockImport};

/// Mock for `TriggerParentchainBlockImport`, to be used in unit tests.
///
/// Allows setting the latest imported block, which is returned upon calling
/// the import methods.
pub struct TriggerParentchainBlockImportMock<SignedBlockType> {
	latest_imported: Option<SignedBlockType>,
	import_has_been_called: RwLock<bool>,
}

impl<SignedBlockType> TriggerParentchainBlockImportMock<SignedBlockType> {
	pub fn with_latest_imported(mut self, maybe_block: Option<SignedBlockType>) -> Self {
		self.latest_imported = maybe_block;
		self
	}

	pub fn has_import_been_called(&self) -> bool {
		let import_flag = self.import_has_been_called.read().unwrap();
		*import_flag
	}
}

impl<SignedBlockType> Default for TriggerParentchainBlockImportMock<SignedBlockType> {
	fn default() -> Self {
		TriggerParentchainBlockImportMock {
			latest_imported: None,
			import_has_been_called: RwLock::new(false),
		}
	}
}

impl<SignedBlockType> TriggerParentchainBlockImport
	for TriggerParentchainBlockImportMock<SignedBlockType>
where
	SignedBlockType: Clone,
{
	type SignedBlockType = SignedBlockType;

	fn import_all(&self) -> Result<Option<SignedBlockType>> {
		let mut import_flag = self.import_has_been_called.write().unwrap();
		*import_flag = true;
		Ok(self.latest_imported.clone())
	}

	fn import_all_but_latest(&self) -> Result<()> {
		let mut import_flag = self.import_has_been_called.write().unwrap();
		*import_flag = true;
		Ok(())
	}

	fn import_until(
		&self,
		_predicate: impl Fn(&SignedBlockType) -> bool,
	) -> Result<Option<SignedBlockType>> {
		let mut import_flag = self.import_has_been_called.write().unwrap();
		*import_flag = true;
		Ok(self.latest_imported.clone())
	}

	fn peek(
		&self,
		predicate: impl Fn(&SignedBlockType) -> bool,
	) -> Result<Option<SignedBlockType>> {
		match &self.latest_imported {
			None => Ok(None),
			Some(block) => {
				if predicate(block) {
					return Ok(Some(block.clone()))
				}
				Ok(None)
			},
		}
	}

	fn peek_latest(&self) -> Result<Option<SignedBlockType>> {
		Ok(self.latest_imported.clone())
	}
}
