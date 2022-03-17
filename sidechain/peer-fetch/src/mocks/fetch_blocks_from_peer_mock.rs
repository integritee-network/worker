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

use crate::{FetchBlocksFromPeer, Result};
use async_trait::async_trait;
use its_primitives::{
	traits::SignedBlock as SignedBlockTrait,
	types::{BlockHash, ShardIdentifier},
};
use std::collections::HashMap;

pub struct FetchBlocksFromPeerMock<SignedBlock> {
	signed_blocks_map: HashMap<ShardIdentifier, Vec<SignedBlock>>,
}

impl<SignedBlock> FetchBlocksFromPeerMock<SignedBlock> {
	pub fn with_signed_blocks(
		mut self,
		blocks_map: HashMap<ShardIdentifier, Vec<SignedBlock>>,
	) -> Self {
		self.signed_blocks_map = blocks_map;
		self
	}
}

impl<SignedBlock> Default for FetchBlocksFromPeerMock<SignedBlock> {
	fn default() -> Self {
		FetchBlocksFromPeerMock { signed_blocks_map: HashMap::new() }
	}
}

#[async_trait]
impl<SignedBlock> FetchBlocksFromPeer for FetchBlocksFromPeerMock<SignedBlock>
where
	SignedBlock: SignedBlockTrait,
{
	type SignedBlockType = SignedBlock;

	async fn fetch_blocks_from_peer(
		&self,
		_last_known_block_hash: BlockHash,
		shard_identifier: ShardIdentifier,
	) -> Result<Vec<Self::SignedBlockType>> {
		Ok(self.signed_blocks_map.get(&shard_identifier).cloned().unwrap_or_default())
	}
}
