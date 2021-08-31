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
use log::*;
#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use parking_lot::RwLock;

use std::path::PathBuf;
use substratee_worker_primitives::block::{BlockNumber, SignedBlock as SignedSidechainBlock};

/// Lock wrapper around sidechain storage
pub struct SidechainStorageLock {
	storage: RwLock<SidechainStorage>,
}

impl SidechainStorageLock {
	pub fn new(path: PathBuf) -> Result<SidechainStorageLock> {
		Ok(SidechainStorageLock { storage: RwLock::new(SidechainStorage::new(path)?) })
	}
}

/// Interface Trait
#[cfg_attr(test, automock)]
pub trait BlockStorage {
	fn store_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> Result<()>;
	fn prune_blocks_except(&self, blocks_to_keep: u64);
}

impl BlockStorage for SidechainStorageLock {
	fn store_blocks(&self, blocks: Vec<SignedSidechainBlock>) -> Result<()> {
		self.storage.write().store_blocks(blocks)
	}

	fn prune_blocks_except(&self, blocks_to_keep: BlockNumber) {
		let mut storage = self.storage.write();
		// prune all shards:
		for shard in storage.shards().clone() {
			// get last block:
			if let Some(last_block) = storage.last_block_of_shard(&shard) {
				let threshold_block = last_block.number - blocks_to_keep;
				if let Err(e) = storage.purge_shard_from_block_number(&shard, threshold_block) {
					error!("Could not purge shard {:?} due to {:?}", shard, e);
				}
			}
		}
	}
}
