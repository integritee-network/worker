/*
	Copyright 2019 Supercomputing Systems AG
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
use super::{storage::SidechainStorage, Result};
use codec::{Decode, Encode};
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use parking_lot::RwLock;
use std::path::PathBuf;
use substratee_worker_primitives::{
	block::{BlockNumber, SignedBlock as SignedSidechainBlock},
	traits::SignedBlock as SignedBlockT,
};

/// Lock wrapper around sidechain storage
pub struct SidechainStorageLock<SignedBlock: SignedBlockT + Encode + Decode> {
	storage: RwLock<SidechainStorage<SignedBlock>>,
}

impl<SignedBlock: SignedBlockT + Encode + Decode> SidechainStorageLock<SignedBlock> {
	pub fn new(path: PathBuf) -> Result<SidechainStorageLock<SignedBlock>> {
		Ok(SidechainStorageLock {
			storage: RwLock::new(SidechainStorage::<SignedBlock>::new(path)?),
		})
	}
}

/// Storage interface Trait¨
/// FIXME: Clean up these traits (generic? non generic? type?)
#[cfg_attr(test, automock)]
pub trait BlockStorage<SignedBlock: SignedBlockT + Encode + Decode> {
	// type not working because gossiper needs to work with the same block type,
	// so it needs to be defined somewhere more global.
	// type SignedBlock: SignedBlockT + Encode + Decode;
	fn store_blocks(&self, blocks: Vec<SignedBlock>) -> Result<()>;
}

/// FIXME: Remove Helper trait (not generic) as soon as sidechain struct have been cleaned up some
pub trait BlockPruner {
	fn prune_blocks_except(&self, blocks_to_keep: u64);
}

impl<SignedBlock: SignedBlockT + Encode + Decode> BlockStorage<SignedBlock>
	for SidechainStorageLock<SignedBlock>
{
	fn store_blocks(&self, blocks: Vec<SignedBlock>) -> Result<()> {
		self.storage.write().store_blocks(blocks)
	}
}

impl<SignedBlock: SignedBlockT + Encode + Decode> BlockPruner
	for SidechainStorageLock<SignedBlock>
{
	fn prune_blocks_except(&self, blocks_to_keep: BlockNumber) {
		self.storage.write().prune_shards(blocks_to_keep);
	}
}
