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

use crate::storage::SidechainStorage;
use its_primitives::types::SignedBlock as SignedSidechainBlock;
use rocksdb::{Options, DB};
use std::{path::PathBuf, vec::Vec};

/// Test fixture for a DB, cleans itself up when it goes out of scope.
///
/// Use with `_dbFixture`, not `_` - because the latter immediately drops!
pub struct TestDbFixture {
	path: PathBuf,
}

impl TestDbFixture {
	pub fn setup(db_path_str: &str, blocks: Vec<SignedSidechainBlock>) -> Self {
		let handle = TestDbFixture { path: PathBuf::from(db_path_str) };

		let mut sidechain_db =
			SidechainStorage::<SignedSidechainBlock>::new(handle.path.clone()).unwrap();
		sidechain_db.store_blocks(blocks).unwrap();

		handle
	}

	pub fn get_handle(&self) -> SidechainStorage<SignedSidechainBlock> {
		SidechainStorage::<SignedSidechainBlock>::new(self.path.clone()).unwrap()
	}
}

impl Drop for TestDbFixture {
	fn drop(&mut self) {
		// clean up
		let _ = DB::destroy(&Options::default(), self.path.clone()).unwrap();
	}
}
