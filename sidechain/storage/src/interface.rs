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

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

use super::{storage::SidechainStorage, Result};
use its_primitives::{
	traits::{ShardIdentifierFor, SignedBlock as SignedBlockT},
	types::{BlockHash, BlockNumber},
};
use parking_lot::RwLock;
use std::path::PathBuf;

/// Lock wrapper around sidechain storage
pub struct SidechainStorageLock<SignedBlock: SignedBlockT> {
	storage: RwLock<SidechainStorage<SignedBlock>>,
}

impl<SignedBlock: SignedBlockT> SidechainStorageLock<SignedBlock> {
	pub fn new(path: PathBuf) -> Result<SidechainStorageLock<SignedBlock>> {
		Ok(SidechainStorageLock {
			storage: RwLock::new(SidechainStorage::<SignedBlock>::new(path)?),
		})
	}
}

/// Storage interface Trait
#[cfg_attr(test, automock)]
pub trait BlockStorage<SignedBlock: SignedBlockT> {
	// type not working because gossiper needs to work with the same block type,
	// so it needs to be defined somewhere more global.
	// type SignedBlock: SignedBlockT;
	fn store_blocks(&self, blocks: Vec<SignedBlock>) -> Result<()>;
}

pub trait BlockPruner {
	/// Prune all blocks except the newest n, where n = `number_of_blocks_to_keep`.
	fn prune_blocks_except(&self, number_of_blocks_to_keep: u64);
}

#[cfg_attr(test, automock)]
pub trait FetchBlocks<SignedBlock: SignedBlockT> {
	/// Fetch all child blocks of a specified block.
	///
	/// Returns an empty vector if specified block hash cannot be found in storage.
	fn fetch_all_blocks_after(
		&self,
		block_hash: &BlockHash,
		shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>>;
}

impl<SignedBlock: SignedBlockT> BlockStorage<SignedBlock> for SidechainStorageLock<SignedBlock> {
	fn store_blocks(&self, blocks: Vec<SignedBlock>) -> Result<()> {
		self.storage.write().store_blocks(blocks)
	}
}

impl<SignedBlock: SignedBlockT> BlockPruner for SidechainStorageLock<SignedBlock> {
	fn prune_blocks_except(&self, number_of_blocks_to_keep: BlockNumber) {
		self.storage.write().prune_shards(number_of_blocks_to_keep);
	}
}

impl<SignedBlock: SignedBlockT> FetchBlocks<SignedBlock> for SidechainStorageLock<SignedBlock> {
	fn fetch_all_blocks_after(
		&self,
		block_hash: &BlockHash,
		shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>> {
		self.storage.read().get_blocks_after(block_hash, shard_identifier)
	}
}
