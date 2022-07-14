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

use crate::{error::Result, interface::FetchBlocks};
use sidechain_primitives::{
	traits::ShardIdentifierFor,
	types::{BlockHash, SignedBlock},
};

#[derive(Default)]
pub struct FetchBlocksMock {
	blocks_to_be_fetched: Vec<SignedBlock>,
}

impl FetchBlocksMock {
	pub fn with_blocks(mut self, blocks: Vec<SignedBlock>) -> Self {
		self.blocks_to_be_fetched = blocks;
		self
	}
}

impl FetchBlocks<SignedBlock> for FetchBlocksMock {
	fn fetch_all_blocks_after(
		&self,
		_block_hash: &BlockHash,
		_shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>> {
		Ok(self.blocks_to_be_fetched.clone())
	}

	fn fetch_blocks_in_range(
		&self,
		_block_hash_from: &BlockHash,
		_block_hash_until: &BlockHash,
		_shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>> {
		Ok(self.blocks_to_be_fetched.clone())
	}
}
