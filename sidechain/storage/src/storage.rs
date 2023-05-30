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

use super::{db::SidechainDB, Error, Result};
use codec::{Decode, Encode};
use itp_settings::files::SIDECHAIN_STORAGE_PATH;
use its_primitives::{
	traits::{Block as BlockTrait, Header as HeaderTrait, SignedBlock as SignedBlockT},
	types::{BlockHash, BlockNumber},
};
use log::*;
use rocksdb::WriteBatch;
use sp_core::H256;
use std::{collections::HashMap, fmt::Debug, path::PathBuf};

/// key value of sidechain db of last block
const LAST_BLOCK_KEY: &[u8] = b"last_sidechainblock";
/// key value of the stored shards vector
const STORED_SHARDS_KEY: &[u8] = b"stored_shards";

/// ShardIdentifier type
type ShardIdentifierFor<B> =
	<<<B as SignedBlockT>::Block as BlockTrait>::HeaderType as HeaderTrait>::ShardIdentifier;

/// Helper struct, contains the blocknumber
/// and blockhash of the last sidechain block
#[derive(PartialEq, Eq, Clone, Copy, Encode, Decode, Debug, Default)]
pub struct LastSidechainBlock {
	/// hash of the last sidechain block
	pub hash: H256,
	/// block number of the last sidechain block
	pub number: BlockNumber,
}

/// Struct used to insert newly produced sidechainblocks
/// into the database
pub struct SidechainStorage<SignedBlock: SignedBlockT> {
	/// database
	db: SidechainDB,
	/// shards in database
	shards: Vec<ShardIdentifierFor<SignedBlock>>,
	/// map to last sidechain block of every shard
	last_blocks: HashMap<ShardIdentifierFor<SignedBlock>, LastSidechainBlock>,
}

impl<SignedBlock: SignedBlockT> SidechainStorage<SignedBlock> {
	/// Loads or initializes the DB at a given path.
	///
	/// Loads existing shards and their last blocks in memory for better performance.
	pub fn load_from_base_path(base_path: PathBuf) -> Result<SidechainStorage<SignedBlock>> {
		// load db
		let db = SidechainDB::open_default(base_path.join(SIDECHAIN_STORAGE_PATH))?;
		let mut storage = SidechainStorage { db, shards: vec![], last_blocks: HashMap::new() };
		storage.shards = storage.load_shards_from_db()?;
		// get last block of each shard
		for shard in storage.shards.iter() {
			if let Some(last_block) = storage.load_last_block_from_db(shard)? {
				storage.last_blocks.insert(*shard, last_block);
			} else {
				// an empty shard sidechain storage should not exist. Consider deleting this shard from the shards list.
				error!("Sidechain storage of shard {:?} is empty", shard);
			}
		}
		Ok(storage)
	}

	/// gets all shards of currently loaded sidechain db
	pub fn shards(&self) -> &Vec<ShardIdentifierFor<SignedBlock>> {
		&self.shards
	}

	/// gets the last block of the current sidechain DB and the given shard
	pub fn last_block_of_shard(
		&self,
		shard: &ShardIdentifierFor<SignedBlock>,
	) -> Option<&LastSidechainBlock> {
		self.last_blocks.get(shard)
	}

	/// gets the block hash of the sidechain block of the given shard and block number, if there is such a block
	pub fn get_block_hash(
		&self,
		shard: &ShardIdentifierFor<SignedBlock>,
		block_number: BlockNumber,
	) -> Result<Option<BlockHash>> {
		self.db.get((*shard, block_number))
	}

	/// gets the block of the given blockhash, if there is such a block
	#[allow(unused)]
	pub fn get_block(&self, block_hash: &BlockHash) -> Result<Option<SignedBlock>> {
		self.db.get(block_hash)
	}

	/// Get all blocks after (i.e. children of) a specified block.
	pub fn get_blocks_after(
		&self,
		block_hash: &BlockHash,
		shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>> {
		// Ensure we find the block in storage (otherwise we would return all blocks for a specific shard).
		// The exception is, if the hash is the default hash, which represents block 0. In that case we want to return all blocks.
		if block_hash != &BlockHash::default() && self.get_block(block_hash)?.is_none() {
			warn!("Could not find starting block in storage, returning empty vector");
			return Ok(Vec::new())
		}

		// We get the latest block and then traverse the parents until we find our starting block.
		let last_block_of_shard = self.last_block_of_shard(shard_identifier).ok_or_else(|| {
			Error::LastBlockNotFound("Failed to find last block information".to_string())
		})?;
		let latest_block = self.get_block(&last_block_of_shard.hash)?.ok_or_else(|| {
			Error::LastBlockNotFound("Failed to retrieve last block from storage".to_string())
		})?;

		let mut current_block = latest_block;
		let mut blocks_to_return = Vec::<SignedBlock>::new();
		while &current_block.hash() != block_hash {
			let parent_block_hash = current_block.block().header().parent_hash();

			blocks_to_return.push(current_block);

			if parent_block_hash == BlockHash::default() {
				break
			}

			current_block =
				self.get_block(&parent_block_hash)?.ok_or(Error::FailedToFindParentBlock)?;
		}

		// Reverse because we iterate from newest to oldest, but result should be oldest first.
		blocks_to_return.reverse();

		Ok(blocks_to_return)
	}

	/// Get blocks in a range, defined by 'from' and 'until' (result does NOT include the bound defining blocks).
	pub fn get_blocks_in_range(
		&self,
		block_hash_from: &BlockHash,
		block_hash_until: &BlockHash,
		shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Vec<SignedBlock>> {
		let all_blocks_from_lower_bound =
			self.get_blocks_after(block_hash_from, shard_identifier)?;

		Ok(all_blocks_from_lower_bound
			.into_iter()
			.take_while(|b| b.hash() != *block_hash_until)
			.collect())
	}

	/// Update sidechain storage with blocks.
	///
	/// Blocks are iterated through one by one. In case more than one block per shard is included,
	/// be sure to give them in the correct order (oldest first).
	pub fn store_blocks(&mut self, blocks_to_store: Vec<SignedBlock>) -> Result<()> {
		let mut batch = WriteBatch::default();
		let mut new_shard = false;
		for block in blocks_to_store.into_iter() {
			if let Err(e) = self.add_block_to_batch(&block, &mut new_shard, &mut batch) {
				error!("Could not store block {:?} due to: {:?}", block, e);
			};
		}
		// Update stored_shards_key -> vec<shard> only if a new shard was included,
		if new_shard {
			SidechainDB::add_to_batch(&mut batch, STORED_SHARDS_KEY, self.shards().clone());
		}
		// Store everything.
		self.db.write(batch)
	}

	/// purges a shard and its block from the db storage
	pub fn purge_shard(&mut self, shard: &ShardIdentifierFor<SignedBlock>) -> Result<()> {
		// get last block of shard
		let last_block = self.get_last_block_of_shard(shard)?;

		// remove last block from db storage
		let mut batch = WriteBatch::default();
		self.delete_last_block(&mut batch, &last_block, shard);

		// Remove the rest of the blocks from the db
		let mut current_block_number = last_block.number;
		while let Some(previous_block) = self.get_previous_block(shard, current_block_number)? {
			current_block_number = previous_block.number;
			self.delete_block(&mut batch, &previous_block.hash, &current_block_number, shard);
		}
		// Remove shard from list.
		// STORED_SHARDS_KEY -> Vec<(Shard)>
		self.shards.retain(|&x| x != *shard);
		// Add updated shards to batch.
		SidechainDB::add_to_batch(&mut batch, STORED_SHARDS_KEY, &self.shards);
		// Update DB
		self.db.write(batch)
	}

	/// purges a shard and its block from the db storage
	/// FIXME: Add delete functions?
	pub fn prune_shard_from_block_number(
		&mut self,
		shard: &ShardIdentifierFor<SignedBlock>,
		block_number: BlockNumber,
	) -> Result<()> {
		let last_block = self.get_last_block_of_shard(shard)?;
		if last_block.number == block_number {
			// given block number is last block of chain - purge whole shard
			self.purge_shard(shard)
		} else {
			// iterate through chain and add all blocks to WriteBatch (delete cmd)
			let mut batch = WriteBatch::default();
			let mut current_block_number = block_number;
			// Remove blocks from db until no block anymore
			while let Some(block_hash) = self.get_block_hash(shard, current_block_number)? {
				self.delete_block(&mut batch, &block_hash, &current_block_number, shard);
				current_block_number -= 1;
			}
			// Update DB
			self.db.write(batch)
		}
	}

	/// Prunes all shards except for the newest blocks (according to blocknumber).
	pub fn prune_shards(&mut self, number_of_blocks_to_keep: BlockNumber) {
		for shard in self.shards().clone() {
			// get last block:
			if let Some(last_block) = self.last_block_of_shard(&shard) {
				let threshold_block = last_block.number - number_of_blocks_to_keep;
				if let Err(e) = self.prune_shard_from_block_number(&shard, threshold_block) {
					error!("Could not purge shard {:?} due to {:?}", shard, e);
				}
			} else {
				error!("Last block not found in shard {:?}", shard);
			}
		}
	}

	fn add_block_to_batch(
		&mut self,
		signed_block: &SignedBlock,
		new_shard: &mut bool,
		batch: &mut WriteBatch,
	) -> Result<()> {
		let shard = &signed_block.block().header().shard_id();
		if self.shards.contains(shard) {
			if !self.verify_block_ancestry(signed_block.block()) {
				// Do not include block if its not a direct ancestor of the last block in line.
				return Err(Error::HeaderAncestryMismatch)
			}
		} else {
			self.shards.push(*shard);
			*new_shard = true;
		}
		// Add block to DB batch.
		self.add_last_block(batch, signed_block);
		Ok(())
	}

	fn verify_block_ancestry(&self, block: &<SignedBlock as SignedBlockT>::Block) -> bool {
		let shard = &block.header().shard_id();
		let current_block_nr = block.header().block_number();
		if let Some(last_block) = self.last_block_of_shard(shard) {
			if last_block.number != current_block_nr - 1 {
				error!("[Sidechain DB] Sidechainblock (nr: {:?}) is not a succession of the previous block (nr: {:?}) in shard: {:?}",
				current_block_nr, last_block.number, *shard);
				return false
			}
		} else {
			error!(
				"[Sidechain DB] Shard {:?} does not have a last block. Skipping block (nr: {:?}) inclusion",
				*shard, current_block_nr
			);
			return false
		}
		true
	}

	/// Implementations of helper functions, not meant for pub use
	/// gets the previous block of given shard and block number, if there is one.
	fn get_previous_block(
		&self,
		shard: &ShardIdentifierFor<SignedBlock>,
		current_block_number: BlockNumber,
	) -> Result<Option<LastSidechainBlock>> {
		let prev_block_number = current_block_number - 1;
		Ok(self
			.get_block_hash(shard, prev_block_number)?
			.map(|block_hash| LastSidechainBlock { hash: block_hash, number: prev_block_number }))
	}
	fn load_shards_from_db(&self) -> Result<Vec<ShardIdentifierFor<SignedBlock>>> {
		Ok(self.db.get(STORED_SHARDS_KEY)?.unwrap_or_default())
	}

	fn load_last_block_from_db(
		&self,
		shard: &ShardIdentifierFor<SignedBlock>,
	) -> Result<Option<LastSidechainBlock>> {
		self.db.get((LAST_BLOCK_KEY, *shard))
	}

	fn get_last_block_of_shard(
		&self,
		shard: &ShardIdentifierFor<SignedBlock>,
	) -> Result<LastSidechainBlock> {
		match self.last_blocks.get(shard) {
			Some(last_block) => Ok(*last_block),
			None => {
				// Try to read from db:
				self.load_last_block_from_db(shard)?
					.ok_or_else(|| Error::LastBlockNotFound(format!("{:?}", *shard)))
			},
		}
	}

	/// Adds the block to the WriteBatch.
	fn add_last_block(&mut self, batch: &mut WriteBatch, block: &SignedBlock) {
		let hash = block.hash();
		let block_number = block.block().header().block_number();
		let shard = block.block().header().shard_id();
		// Block hash -> Signed Block.
		SidechainDB::add_to_batch(batch, hash, block);

		// (Shard, Block number) -> Blockhash (for block pruning).
		SidechainDB::add_to_batch(batch, (shard, block_number), hash);

		// (last_block_key, shard) -> (Blockhash, BlockNr) current blockchain state.
		let last_block = LastSidechainBlock { hash, number: block_number };
		self.last_blocks.insert(shard, last_block); // add in memory
		SidechainDB::add_to_batch(batch, (LAST_BLOCK_KEY, shard), last_block);
	}

	/// Add delete block to the WriteBatch.
	fn delete_block(
		&self,
		batch: &mut WriteBatch,
		block_hash: &H256,
		block_number: &BlockNumber,
		shard: &ShardIdentifierFor<SignedBlock>,
	) {
		// Block hash -> Signed Block.
		SidechainDB::delete_to_batch(batch, block_hash);
		// (Shard, Block number) -> Blockhash (for block pruning).
		SidechainDB::delete_to_batch(batch, (shard, block_number));
	}

	/// Add delete command to remove last block to WriteBatch and remove it from memory.
	///
	/// This includes adding a delete command of the following:
	/// - Block hash -> Signed Block.
	/// - (Shard, Block number) -> Blockhash (for block pruning).
	/// - ((LAST_BLOCK_KEY, shard) -> BlockHash) -> Blockhash (for block pruning).
	///
	/// Careful usage of this command: In case the last block is deleted, (LAST_BLOCK_KEY, shard) will be empty
	/// even though there might be a new last block (i.e. the previous block of the removed last block).
	fn delete_last_block(
		&mut self,
		batch: &mut WriteBatch,
		last_block: &LastSidechainBlock,
		shard: &ShardIdentifierFor<SignedBlock>,
	) {
		// Add delete block to batch.
		// (LAST_BLOCK_KEY, Shard) -> LastSidechainBlock.
		SidechainDB::delete_to_batch(batch, (LAST_BLOCK_KEY, *shard));
		self.delete_block(batch, &last_block.hash, &last_block.number, shard);

		// Delete last block from local memory.
		// Careful here: This deletes the local memory before db has been actually pruned
		// (it's only been added to the write batch).
		// But this can be fixed upon reloading the db / restarting the worker.
		self.last_blocks.remove(shard);
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::test_utils::{
		create_signed_block_with_shard as create_signed_block, create_temp_dir, get_storage,
	};
	use itp_types::ShardIdentifier;
	use its_primitives::{traits::SignedBlock as SignedBlockT, types::SignedBlock};
	use sp_core::H256;

	#[test]
	fn load_shards_from_db_works() {
		// given
		let temp_dir = create_temp_dir();
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		// when
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// ensure db starts empty
			assert_eq!(sidechain_db.load_shards_from_db().unwrap(), vec![]);
			// write signed_block to db
			sidechain_db.db.put(STORED_SHARDS_KEY, vec![shard_one, shard_two]).unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let loaded_shards = updated_sidechain_db.load_shards_from_db().unwrap();
			assert!(loaded_shards.contains(&shard_one));
			assert!(loaded_shards.contains(&shard_two));
		}
	}

	#[test]
	fn load_last_block_from_db_works() {
		// given
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(20, shard);
		let signed_last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		// when
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// ensure db starts empty
			assert!(sidechain_db.load_last_block_from_db(&shard).unwrap().is_none());
			// write signed_block to db
			sidechain_db.db.put((LAST_BLOCK_KEY, shard), signed_last_block.clone()).unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let loaded_block =
				updated_sidechain_db.load_last_block_from_db(&shard).unwrap().unwrap();
			assert_eq!(loaded_block, signed_last_block);
		}
	}

	#[test]
	fn create_new_sidechain_storage_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let shard_vector = vec![shard];
		let signed_block = create_signed_block(20, shard);
		let signed_last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// ensure db starts empty
			assert!(sidechain_db.load_last_block_from_db(&shard).unwrap().is_none());
			// write shards to db
			sidechain_db.db.put((LAST_BLOCK_KEY, shard), signed_last_block.clone()).unwrap();
			// write shards to db
			sidechain_db.db.put(STORED_SHARDS_KEY, shard_vector.clone()).unwrap();
		}

		{
			// open new DB of same path:
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			assert_eq!(updated_sidechain_db.shards, shard_vector);
			assert_eq!(*updated_sidechain_db.last_blocks.get(&shard).unwrap(), signed_last_block);
		}
	}

	#[test]
	fn add_last_block_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);

		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let mut batch = WriteBatch::default();
			sidechain_db.add_last_block(&mut batch, &signed_block);
			sidechain_db.db.write(batch).unwrap();

			// ensure DB contains previously stored data:
			let last_block = sidechain_db.last_block_of_shard(&shard).unwrap();
			assert_eq!(last_block.number, signed_block.block().header().block_number());
			assert_eq!(last_block.hash, signed_block.hash());
			let stored_block_hash =
				sidechain_db.get_block_hash(&shard, last_block.number).unwrap().unwrap();
			assert_eq!(stored_block_hash, signed_block.hash());
			assert_eq!(sidechain_db.get_block(&stored_block_hash).unwrap().unwrap(), signed_block);
		}
	}

	#[test]
	fn delete_block_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		{
			// fill db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.db.put(signed_block.hash(), signed_block.clone()).unwrap();
			sidechain_db
				.db
				.put((shard, signed_block.block().header().block_number()), signed_block.hash())
				.unwrap();
			assert_eq!(
				sidechain_db
					.db
					.get::<(ShardIdentifier, BlockNumber), H256>((
						shard,
						signed_block.block().header().block_number()
					))
					.unwrap()
					.unwrap(),
				signed_block.hash()
			);
			assert_eq!(
				sidechain_db.db.get::<H256, SignedBlock>(signed_block.hash()).unwrap().unwrap(),
				signed_block
			);

			// when
			let mut batch = WriteBatch::default();
			sidechain_db.delete_block(
				&mut batch,
				&signed_block.hash(),
				&signed_block.block().header().block_number(),
				&shard,
			);
			sidechain_db.db.write(batch).unwrap();
		}

		{
			// open new DB of same path:
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// ensure DB does not contain block anymore:
			assert!(updated_sidechain_db
				.db
				.get::<(ShardIdentifier, BlockNumber), H256>((
					shard,
					signed_block.block().header().block_number()
				))
				.unwrap()
				.is_none());
			assert!(updated_sidechain_db
				.db
				.get::<H256, SignedBlock>(signed_block.hash())
				.unwrap()
				.is_none());
		}
	}

	#[test]
	fn delete_last_block_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		{
			// fill db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.db.put(signed_block.hash(), signed_block.clone()).unwrap();
			sidechain_db
				.db
				.put((shard, signed_block.block().header().block_number()), signed_block.hash())
				.unwrap();
			sidechain_db.db.put((LAST_BLOCK_KEY, shard), last_block.clone()).unwrap();
			assert_eq!(
				sidechain_db
					.db
					.get::<(ShardIdentifier, BlockNumber), H256>((
						shard,
						signed_block.block().header().block_number()
					))
					.unwrap()
					.unwrap(),
				signed_block.hash()
			);
			assert_eq!(
				sidechain_db.db.get::<H256, SignedBlock>(signed_block.hash()).unwrap().unwrap(),
				signed_block
			);
			assert_eq!(
				sidechain_db
					.db
					.get::<(&[u8], ShardIdentifier), LastSidechainBlock>((LAST_BLOCK_KEY, shard))
					.unwrap()
					.unwrap(),
				last_block
			);

			// when
			let mut batch = WriteBatch::default();
			sidechain_db.delete_last_block(&mut batch, &last_block, &shard);
			sidechain_db.db.write(batch).unwrap();

			// then
			assert!(sidechain_db.last_blocks.get(&shard).is_none());
			assert!(sidechain_db
				.db
				.get::<(ShardIdentifier, BlockNumber), H256>((
					shard,
					signed_block.block().header().block_number()
				))
				.unwrap()
				.is_none());
			assert!(sidechain_db
				.db
				.get::<H256, SignedBlock>(signed_block.hash())
				.unwrap()
				.is_none());
			assert!(sidechain_db
				.db
				.get::<(&[u8], ShardIdentifier), LastSidechainBlock>((LAST_BLOCK_KEY, shard))
				.unwrap()
				.is_none());
		}
	}

	#[test]
	fn verify_block_ancestry_returns_true_if_correct_successor() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		let signed_block_two = create_signed_block(9, shard);
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.shards.push(shard);
			sidechain_db.last_blocks.insert(shard, last_block);
			// when
			let result = sidechain_db.verify_block_ancestry(&signed_block_two.block());

			// then
			assert!(result);
		}
	}

	#[test]
	fn verify_block_ancestry_returns_false_if_not_correct_successor() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		let signed_block_two = create_signed_block(5, shard);
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.shards.push(shard);
			sidechain_db.last_blocks.insert(shard, last_block);

			// when
			let result = sidechain_db.verify_block_ancestry(&signed_block_two.block());

			// then
			assert!(!result);
		}
	}

	#[test]
	fn verify_block_ancestry_returns_false_no_last_block_registered() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.shards.push(shard);
			// when
			let result = sidechain_db.verify_block_ancestry(&signed_block.block());

			// then
			assert!(!result);
		}
	}

	#[test]
	fn verify_block_ancestry_returns_false_if_no_shard() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		{
			let sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let result = sidechain_db.verify_block_ancestry(&signed_block.block());
			assert!(!result);
		}
	}

	#[test]
	fn add_block_to_batch_works_with_new_shard() {
		// given
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let mut new_shard = false;
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let mut batch = WriteBatch::default();
			assert!(batch.is_empty());

			sidechain_db
				.add_block_to_batch(&signed_block, &mut new_shard, &mut batch)
				.unwrap();

			assert!(new_shard);
			assert!(!batch.is_empty());
		}
	}

	#[test]
	fn add_block_to_batch_does_not_add_shard_if_existent() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		let signed_block_two = create_signed_block(9, shard);
		let mut new_shard = false;
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let mut batch = WriteBatch::default();
			assert!(batch.is_empty());
			sidechain_db.shards.push(shard);
			sidechain_db.last_blocks.insert(shard, last_block);

			sidechain_db
				.add_block_to_batch(&signed_block_two, &mut new_shard, &mut batch)
				.unwrap();

			assert!(!new_shard);
			assert!(!batch.is_empty());
		}
	}

	#[test]
	fn add_block_to_batch_does_not_add_block_if_not_ancestor() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(8, shard);
		let last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().header().block_number(),
		};
		let signed_block_two = create_signed_block(10, shard);
		let mut new_shard = false;
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			let mut batch = WriteBatch::default();
			sidechain_db.shards.push(shard);
			sidechain_db.last_blocks.insert(shard, last_block);

			let result =
				sidechain_db.add_block_to_batch(&signed_block_two, &mut new_shard, &mut batch);

			assert!(result.is_err());
			assert!(!new_shard);
			assert!(batch.is_empty());
		}
	}

	#[test]
	fn store_block_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(20, shard);
		let signed_block_vector: Vec<SignedBlock> = vec![signed_block.clone()];

		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// db needs to start empty
			assert_eq!(sidechain_db.shards, vec![]);
			sidechain_db.store_blocks(signed_block_vector).unwrap();
		}

		{
			// open new DB of same path:
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// ensure DB contains previously stored data:
			assert_eq!(*updated_sidechain_db.shards(), vec![shard]);
			let last_block = updated_sidechain_db.last_block_of_shard(&shard).unwrap();
			assert_eq!(last_block.number, signed_block.block().header().block_number());
			assert_eq!(last_block.hash, signed_block.hash());
			let stored_block_hash =
				updated_sidechain_db.get_block_hash(&shard, last_block.number).unwrap().unwrap();
			assert_eq!(stored_block_hash, signed_block.hash());
			assert_eq!(
				updated_sidechain_db.get_block(&stored_block_hash).unwrap().unwrap(),
				signed_block
			);
		}
	}

	#[test]
	fn store_blocks_on_multi_sharding_works() {
		let temp_dir = create_temp_dir();
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		let signed_block_one = create_signed_block(20, shard_one);
		let signed_block_two = create_signed_block(1, shard_two);

		let signed_block_vector: Vec<SignedBlock> =
			vec![signed_block_one.clone(), signed_block_two.clone()];

		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// db needs to start empty
			assert_eq!(sidechain_db.shards, vec![]);
			sidechain_db.store_blocks(signed_block_vector).unwrap();
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			assert_eq!(updated_sidechain_db.shards()[0], shard_one);
			assert_eq!(updated_sidechain_db.shards()[1], shard_two);
			let last_block_one: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_one).unwrap();
			let last_block_two: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_two).unwrap();
			assert_eq!(last_block_one.number, 20);
			assert_eq!(last_block_two.number, 1);
			assert_eq!(last_block_one.hash, signed_block_one.hash());
			assert_eq!(last_block_two.hash, signed_block_two.hash());
		}
	}

	#[test]
	fn store_mulitple_block_on_one_shard_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(20, shard);
		let signed_block_two = create_signed_block(21, shard);
		let signed_block_vector_one = vec![signed_block_one.clone()];
		let signed_block_vector_two = vec![signed_block_two.clone()];

		{
			// first iteration
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(signed_block_vector_one).unwrap();
		}
		{
			// second iteration
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(signed_block_vector_two).unwrap();
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// last block is really equal to second block:
			let last_block: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard).unwrap();
			assert_eq!(last_block.number, 21);
			// storage contains both blocks:
			// (shard,blocknumber) -> blockhash
			let db_block_hash_one =
				updated_sidechain_db.get_block_hash(&shard, 20).unwrap().unwrap();
			let db_block_hash_two =
				updated_sidechain_db.get_block_hash(&shard, 21).unwrap().unwrap();
			assert_eq!(db_block_hash_one, signed_block_one.hash());
			assert_eq!(db_block_hash_two, signed_block_two.hash());

			// block hash -> signed block
			let db_block_one =
				updated_sidechain_db.get_block(&signed_block_one.hash()).unwrap().unwrap();
			let db_block_two =
				updated_sidechain_db.get_block(&signed_block_two.hash()).unwrap().unwrap();
			assert_eq!(db_block_one, signed_block_one);
			assert_eq!(db_block_two, signed_block_two);
		}
	}

	#[test]
	fn wrong_succession_order_does_not_get_accepted() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(7, shard);
		let signed_block_two = create_signed_block(21, shard);
		let signed_block_vector_one = vec![signed_block_one.clone()];
		let signed_block_vector_two = vec![signed_block_two.clone()];

		{
			// first iteration
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(signed_block_vector_one).unwrap();
		}
		{
			// second iteration
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(signed_block_vector_two).unwrap();
		}
		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// last block is equal to first block:
			let last_block: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard).unwrap();
			assert_eq!(last_block.number, signed_block_one.block().header().block_number());

			// storage contains only one blocks:
			// (shard,blocknumber) -> blockhash
			let db_block_hash_one = updated_sidechain_db
				.get_block_hash(&shard, signed_block_one.block().header().block_number())
				.unwrap()
				.unwrap();
			let db_block_hash_empty = updated_sidechain_db
				.get_block_hash(&shard, signed_block_two.block().header().block_number())
				.unwrap();
			assert!(db_block_hash_empty.is_none());
			assert_eq!(db_block_hash_one, signed_block_one.hash());
		}
	}

	#[test]
	fn get_previous_block_returns_correct_block() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(1, shard);
		// create sidechain_db
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![signed_block_one.clone()]).unwrap();
			// create last block one for comparison
			let last_block = LastSidechainBlock {
				hash: signed_block_one.hash(),
				number: signed_block_one.block().header().block_number(),
			};

			// then
			let some_block = sidechain_db
				.get_previous_block(&shard, signed_block_one.block().header().block_number() + 1)
				.unwrap()
				.unwrap();

			// when
			assert_eq!(some_block, last_block);
		}
	}

	#[test]
	fn get_previous_block_returns_none_when_no_block() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		{
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![create_signed_block(1, shard)]).unwrap();

			let no_block = sidechain_db.get_previous_block(&shard, 1).unwrap();

			assert!(no_block.is_none());
		}
	}

	#[test]
	fn purge_shard_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		{
			// create sidechain_db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			sidechain_db.purge_shard(&shard).unwrap();

			// test if local storage has been cleansed
			assert!(!sidechain_db.shards.contains(&shard));
			assert!(sidechain_db.last_blocks.get(&shard).is_none());
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// test if local storage is still clean
			assert!(!updated_sidechain_db.shards.contains(&shard));
			assert!(updated_sidechain_db.last_blocks.get(&shard).is_none());
			// test if db is clean
			assert!(updated_sidechain_db.last_block_of_shard(&shard).is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 3).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 2).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 1).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_one.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_two.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_three.hash()).unwrap().is_none());
		}
	}

	#[test]
	fn purge_shard_from_block_works() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		let last_block = LastSidechainBlock {
			hash: block_three.hash(),
			number: block_three.block().header().block_number(),
		};

		{
			// create sidechain_db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			sidechain_db.prune_shard_from_block_number(&shard, 2).unwrap();
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// test local memory
			assert!(updated_sidechain_db.shards.contains(&shard));
			assert_eq!(*updated_sidechain_db.last_blocks.get(&shard).unwrap(), last_block);
			// assert block three is still there
			assert_eq!(*updated_sidechain_db.last_block_of_shard(&shard).unwrap(), last_block);
			assert_eq!(
				updated_sidechain_db.get_block_hash(&shard, 3).unwrap().unwrap(),
				block_three.hash()
			);
			assert_eq!(
				updated_sidechain_db.get_block(&block_three.hash()).unwrap().unwrap(),
				block_three
			);
			// assert the lower blocks have been purged
			assert!(updated_sidechain_db.get_block_hash(&shard, 2).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 1).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_two.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_one.hash()).unwrap().is_none());
		}
	}

	#[test]
	fn purge_shard_from_block_works_for_last_block() {
		let temp_dir = create_temp_dir();
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		{
			// create sidechain_db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			sidechain_db.prune_shard_from_block_number(&shard, 3).unwrap();

			// test if local storage has been cleansed
			assert!(!sidechain_db.shards.contains(&shard));
			assert!(sidechain_db.last_blocks.get(&shard).is_none());
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// test if local storage is still clean
			assert!(!updated_sidechain_db.shards.contains(&shard));
			assert!(updated_sidechain_db.last_blocks.get(&shard).is_none());
			// test if db is clean
			assert!(updated_sidechain_db.last_block_of_shard(&shard).is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 3).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 2).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard, 1).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_one.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_two.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_three.hash()).unwrap().is_none());
		}
	}

	#[test]
	fn prune_shards_works_for_multiple_shards() {
		let temp_dir = create_temp_dir();
		// shard one
		let shard_one = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard_one);
		let block_two = create_signed_block(2, shard_one);
		let block_three = create_signed_block(3, shard_one);
		let last_block_one = LastSidechainBlock {
			hash: block_three.hash(),
			number: block_three.block().header().block_number(),
		};
		// shard two
		let shard_two = H256::from_low_u64_be(2);
		let block_one_s = create_signed_block(1, shard_two);
		let block_two_s = create_signed_block(2, shard_two);
		let block_three_s = create_signed_block(3, shard_two);
		let block_four_s = create_signed_block(4, shard_two);
		let last_block_two = LastSidechainBlock {
			hash: block_four_s.hash(),
			number: block_four_s.block().header().block_number(),
		};
		{
			// create sidechain_db
			let mut sidechain_db = get_storage(temp_dir.path().to_path_buf());
			sidechain_db.store_blocks(vec![block_one.clone(), block_one_s.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone(), block_two_s.clone()]).unwrap();
			sidechain_db
				.store_blocks(vec![block_three.clone(), block_three_s.clone()])
				.unwrap();
			sidechain_db.store_blocks(vec![block_four_s.clone()]).unwrap();

			sidechain_db.prune_shards(2);
		}

		{
			let updated_sidechain_db = get_storage(temp_dir.path().to_path_buf());
			// test if shard one has been cleansed of block 1, with 2 and 3 still beeing there:
			assert_eq!(
				*updated_sidechain_db.last_block_of_shard(&shard_one).unwrap(),
				last_block_one
			);
			assert_eq!(
				updated_sidechain_db.get_block_hash(&shard_one, 3).unwrap().unwrap(),
				block_three.hash()
			);
			assert_eq!(
				updated_sidechain_db.get_block(&block_three.hash()).unwrap().unwrap(),
				block_three
			);
			assert_eq!(
				updated_sidechain_db.get_block_hash(&shard_one, 2).unwrap().unwrap(),
				block_two.hash()
			);
			assert_eq!(
				updated_sidechain_db.get_block(&block_two.hash()).unwrap().unwrap(),
				block_two
			);
			assert!(updated_sidechain_db.get_block(&block_one.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard_one, 1).unwrap().is_none());
			// test if shard two has been cleansed of block 1 and 2, with 3 and 4 still beeing there:
			assert_eq!(
				*updated_sidechain_db.last_block_of_shard(&shard_two).unwrap(),
				last_block_two
			);
			assert_eq!(
				updated_sidechain_db.get_block_hash(&shard_two, 4).unwrap().unwrap(),
				block_four_s.hash()
			);
			assert_eq!(
				updated_sidechain_db.get_block(&block_four_s.hash()).unwrap().unwrap(),
				block_four_s
			);
			assert_eq!(
				updated_sidechain_db.get_block_hash(&shard_two, 3).unwrap().unwrap(),
				block_three_s.hash()
			);
			assert_eq!(
				updated_sidechain_db.get_block(&block_three_s.hash()).unwrap().unwrap(),
				block_three_s
			);
			assert!(updated_sidechain_db.get_block_hash(&shard_two, 2).unwrap().is_none());
			assert!(updated_sidechain_db.get_block_hash(&shard_two, 1).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_one_s.hash()).unwrap().is_none());
			assert!(updated_sidechain_db.get_block(&block_two_s.hash()).unwrap().is_none());
		}
	}
}
