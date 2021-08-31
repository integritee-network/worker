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

use super::{Error, Result};
use codec::{Decode, Encode};
use log::*;
use rocksdb::{WriteBatch, DB};
use sp_core::H256;
use std::{collections::HashMap, path::PathBuf};
use substratee_node_primitives::ShardIdentifier;
use substratee_worker_primitives::{
	block::{BlockHash, BlockNumber, SignedBlock as SignedSidechainBlock},
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait},
};

/// key value of sidechain db of last block
const LAST_BLOCK_KEY: &[u8] = b"last_sidechainblock";
/// key value of the stored shards vector
const STORED_SHARDS_KEY: &[u8] = b"stored_shards";

/// Sidechain DB Storage structure:
/// STORED_SHARDS_KEY -> Vec<(Shard)>
/// (LAST_BLOCK_KEY, Shard) -> (Blockhash, BlockNr) (look up current blockchain state)
/// (Shard , Block number) -> Blockhash (needed for block pruning)
/// Blockhash -> Signed Block (actual block storage)

/// Helper struct, contains the blocknumber
/// and blockhash of the last sidechain block
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug, Default)]
pub struct LastSidechainBlock {
	/// hash of the last sidechain block
	pub hash: H256,
	/// block number of the last sidechain block
	pub number: BlockNumber,
}

/// Struct used to insert newly produced sidechainblocks
/// into the database
pub struct SidechainStorage {
	/// database
	db: DB,
	/// shards in database
	shards: Vec<ShardIdentifier>,
	/// map to last sidechain block of every shard
	last_blocks: HashMap<ShardIdentifier, LastSidechainBlock>,
}

impl SidechainStorage {
	/// loads the DB from the given paths and stores the listed shard
	/// and their last blocks in memory for better performance
	pub fn new(path: PathBuf) -> Result<SidechainStorage> {
		// load db
		let db = DB::open_default(path).unwrap();
		let shards = Self::load_shards_from_db(&db)?;
		// get last block of each shard
		let mut last_blocks = HashMap::new();
		for shard in shards.iter() {
			if let Some(last_block) = Self::load_last_block_from_db(&db, shard)? {
				last_blocks.insert(*shard, last_block);
			} else {
				// an empty shard sidechain storage should not exist. Consider deleting this shard from the shards list.
				error!("Sidechain storage of shard {:?} is empty", shard);
			}
		}
		Ok(SidechainStorage { db, shards, last_blocks })
	}

	/// gets all shards of currently loaded sidechain db
	pub fn shards(&self) -> &Vec<ShardIdentifier> {
		&self.shards
	}

	/// gets the last block of the current sidechain DB and the given shard
	pub fn last_block_of_shard(&self, shard: &ShardIdentifier) -> Option<&LastSidechainBlock> {
		self.last_blocks.get(shard)
	}

	/// gets the block hash of the sidechain block of the given shard and block number, if there is such a block
	pub fn get_block_hash(
		&self,
		shard: &ShardIdentifier,
		block_number: BlockNumber,
	) -> Result<Option<BlockHash>> {
		match self.db.get((*shard, block_number).encode()).map_err(Error::OperationalError)? {
			None => Ok(None),
			Some(enocded_hash) => Ok(Some(
				BlockHash::decode(&mut enocded_hash.as_slice()).map_err(Error::DecodeError)?,
			)),
		}
	}

	/// gets the block of the given blockhash, if there is such a block
	#[allow(unused)]
	pub fn get_block(&self, block_hash: &BlockHash) -> Result<Option<SignedSidechainBlock>> {
		match self.db.get(block_hash.encode()).map_err(Error::OperationalError)? {
			None => Ok(None),
			Some(enocded_hash) => Ok(Some(
				SignedSidechainBlock::decode(&mut enocded_hash.as_slice())
					.map_err(Error::DecodeError)?,
			)),
		}
	}

	/// update sidechain storage
	pub fn store_blocks(&mut self, blocks_to_store: Vec<SignedSidechainBlock>) -> Result<()> {
		println! {"Received blocks: {:?}", blocks_to_store};
		let mut batch = WriteBatch::default();
		let mut new_shard = false;
		for signed_block in blocks_to_store.into_iter() {
			// check if current block is the next in line
			let current_block_shard = signed_block.block().shard_id();
			let current_block_nr = signed_block.block().block_number();
			if self.shards.contains(&current_block_shard) {
				if let Some(last_block) = self.last_block_of_shard(&current_block_shard) {
					if last_block.number != current_block_nr - 1 {
						error!("The to be included sidechainblock number {:?} is not a succession of the previous sidechain block in the db: {:?}",
						current_block_nr, last_block.number);
						continue
					}
				} else {
					error!(
						"A shard without a last block is existing. Skipping shard: {:?}",
						current_block_shard
					);
					continue
				}
			} else {
				self.shards.push(current_block_shard);
				new_shard = true;
			}

			// Block hash -> Signed Block
			let current_block_hash = signed_block.hash();
			batch.put(&current_block_hash.encode(), &signed_block.encode().as_slice());
			// (Shard, Block number) -> Blockhash (for block pruning)
			batch.put(
				&(current_block_shard, current_block_nr).encode().as_slice(),
				&current_block_hash.encode(),
			);
			// (last_block_key, shard) -> (Blockhash, BlockNr) current blockchain state
			let current_last_block =
				LastSidechainBlock { hash: current_block_hash, number: current_block_nr };
			self.last_blocks.insert(current_block_shard, current_last_block.clone());
			batch.put((LAST_BLOCK_KEY, current_block_shard).encode(), current_last_block.encode());
		}
		// update stored_shards_key -> vec<shard> only when a new shard was included
		if new_shard {
			batch.put(STORED_SHARDS_KEY.encode(), self.shards.encode());
		}
		if let Err(e) = self.db.write(batch) {
			error!("Could not write batch to sidechain db due to {}", e);
			return Err(Error::OperationalError(e))
		};
		Ok(())
	}

	/// purges a shard and its block from the db storage
	pub fn purge_shard(&mut self, shard: &ShardIdentifier) -> Result<()> {
		if self.shards.contains(shard) {
			// get last block of shard
			let mut last_block = match self.last_blocks.get(shard) {
				Some(last_block) => last_block.clone(),
				None => return Err(Error::LastBlockNotFound(*shard)),
			};
			// remove last block from db storage
			// Blockhash -> Signed Block
			self.db.delete(last_block.hash.encode()).map_err(Error::OperationalError)?;
			// (Shard , Block number) -> Blockhash
			self.db
				.delete((shard, last_block.number).encode())
				.map_err(Error::OperationalError)?;
			// (LAST_BLOCK_KEY, Shard) -> LastSidechainBlock
			self.db
				.delete((LAST_BLOCK_KEY, shard).encode())
				.map_err(Error::OperationalError)?;
			self.last_blocks.remove(&shard); // delete from local memory

			// Remove all blocks from db
			while let Some(previous_block) = self.get_previous_block(shard, last_block.number) {
				last_block = previous_block;
				// Blockhash -> Signed Block
				self.db.delete(last_block.hash.encode()).map_err(Error::OperationalError)?;
				// (Shard, Block number) -> Blockhash
				self.db
					.delete((shard, last_block.number).encode())
					.map_err(Error::OperationalError)?;
			}
			// remove shard from list
			// STORED_SHARDS_KEY -> Vec<(Shard)>
			self.shards.retain(|&x| x != *shard);
			self.db
				.put(STORED_SHARDS_KEY.encode(), self.shards.encode())
				.map_err(Error::OperationalError)?
		}
		Ok(())
	}

	/// purges a shard and its block from the db storage
	pub fn prune_shard_from_block_number(
		&mut self,
		shard: &ShardIdentifier,
		block_number: BlockNumber,
	) -> Result<()> {
		if self.shards.contains(&shard) {
			// get last block of shard
			let last_block = match self.last_blocks.get(shard) {
				Some(last_block) => last_block.clone(),
				None => return Err(Error::LastBlockNotFound(*shard)),
			};
			if last_block.number == block_number {
				// given block number is last block of chain - purge whole shard
				self.purge_shard(shard)?;
			} else {
				// remove given block from db storage
				let mut current_block_number = block_number;

				// Remove blocks from db until no block anymore
				while let Some(block_hash) = self.get_block_hash(&shard, current_block_number)? {
					// Blockhash -> Signed Block
					self.db.delete(block_hash.encode()).map_err(Error::OperationalError)?;
					// (Shard, Block number) -> Blockhash
					self.db
						.delete((shard, current_block_number).encode())
						.map_err(Error::OperationalError)?;
					current_block_number -= 1;
				}
			}
		}
		Ok(())
	}

	/// prunes all shards except for the newest blocks (according to blocknumber)
	pub fn prune_shards(&mut self, blocks_to_keep: BlockNumber) {
		for shard in self.shards().clone() {
			// get last block:
			if let Some(last_block) = self.last_block_of_shard(&shard) {
				let threshold_block = last_block.number - blocks_to_keep;
				if let Err(e) = self.prune_shard_from_block_number(&shard, threshold_block) {
					error!("Could not purge shard {:?} due to {:?}", shard, e);
				}
			} else {
				error!("Last block not found in shard {:?}", shard);
			}
		}
	}
}

/// implementations of helper functions, not meant for pub use
impl SidechainStorage {
	/// gets the previous block of given shard and block number, if there is one
	fn get_previous_block(
		&self,
		shard: &ShardIdentifier,
		current_block_number: BlockNumber,
	) -> Option<LastSidechainBlock> {
		let prev_block_number = current_block_number - 1;
		if let Some(block_hash_encoded) = self.db.get((shard, prev_block_number).encode()).unwrap()
		{
			let block_hash = H256::decode(&mut block_hash_encoded.as_slice()).unwrap();
			Some(LastSidechainBlock { hash: block_hash, number: prev_block_number })
		} else {
			None
		}
	}
	/// reads shards from DB
	fn load_shards_from_db(db: &DB) -> Result<Vec<ShardIdentifier>> {
		match db.get(STORED_SHARDS_KEY.encode()).map_err(Error::OperationalError)? {
			Some(shards) => Ok(Vec::<ShardIdentifier>::decode(&mut shards.as_slice())
				.map_err(Error::DecodeError)?),
			None => Ok(vec![]),
		}
	}

	/// reads last block from DB
	fn load_last_block_from_db(
		db: &DB,
		shard: &ShardIdentifier,
	) -> Result<Option<LastSidechainBlock>> {
		match db.get((LAST_BLOCK_KEY, *shard).encode()).map_err(Error::OperationalError)? {
			Some(last_block_encoded) => Ok(Some(
				LastSidechainBlock::decode(&mut last_block_encoded.as_slice())
					.map_err(Error::DecodeError)?,
			)),
			None => Ok(None),
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use rocksdb::{Options, DB};
	use sp_core::{
		crypto::{AccountId32, Pair},
		ed25519, H256,
	};
	use std::{
		path::PathBuf,
		time::{SystemTime, UNIX_EPOCH},
	};
	use substratee_node_primitives::ShardIdentifier;
	use substratee_worker_primitives::{
		block::{Block, SignedBlock as SignedSidechainBlock},
		traits::{
			Block as SidechainBlockTrait, SignBlock, SignedBlock as SignedSidechainBlockTrait,
		},
	};

	#[test]
	fn load_shards_from_db_works() {
		// given
		let path = PathBuf::from("load_shards_from_db_works");
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		// when
		{
			let sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// ensure db starts empty
			assert_eq!(SidechainStorage::load_shards_from_db(&sidechain_db.db).unwrap(), vec![]);
			// write signed_block to db
			sidechain_db
				.db
				.put(STORED_SHARDS_KEY.encode(), vec![shard_one, shard_two].encode())
				.unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			let loaded_shards =
				SidechainStorage::load_shards_from_db(&updated_sidechain_db.db).unwrap();
			assert!(loaded_shards.contains(&shard_one));
			assert!(loaded_shards.contains(&shard_two));
		}
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn load_last_block_from_db_works() {
		// given
		let path = PathBuf::from("load_last_block_from_db_works");
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(20, shard);
		let signed_last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().block_number(),
		};
		// when
		{
			let sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// ensure db starts empty
			assert!(SidechainStorage::load_last_block_from_db(&sidechain_db.db, &shard)
				.unwrap()
				.is_none());
			// write signed_block to db
			sidechain_db
				.db
				.put((LAST_BLOCK_KEY, shard).encode(), signed_last_block.encode())
				.unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			let loaded_block =
				SidechainStorage::load_last_block_from_db(&updated_sidechain_db.db, &shard)
					.unwrap()
					.unwrap();
			assert_eq!(loaded_block, signed_last_block);
		}
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn create_new_sidechain_storage_works() {
		// given
		let path = PathBuf::from("create_new_sidechain_storage_works");
		let shard = H256::from_low_u64_be(1);
		let shard_vector = vec![shard];
		let signed_block = create_signed_block(20, shard);
		let signed_last_block = LastSidechainBlock {
			hash: signed_block.hash(),
			number: signed_block.block().block_number(),
		};
		// when
		{
			let sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// ensure db starts empty
			assert!(SidechainStorage::load_last_block_from_db(&sidechain_db.db, &shard)
				.unwrap()
				.is_none());
			// write shards to db
			sidechain_db
				.db
				.put((LAST_BLOCK_KEY, shard).encode(), signed_last_block.encode())
				.unwrap();
			// write shards to db
			sidechain_db.db.put(STORED_SHARDS_KEY.encode(), shard_vector.encode()).unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			assert_eq!(updated_sidechain_db.shards, shard_vector);
			assert_eq!(*updated_sidechain_db.last_blocks.get(&shard).unwrap(), signed_last_block);
		}
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn store_block_works() {
		// given
		let path = PathBuf::from("store_block_works");
		let shard = H256::from_low_u64_be(1);
		let signed_block = create_signed_block(20, shard);
		let signed_block_vector: Vec<SignedSidechainBlock> = vec![signed_block.clone()];

		// when
		{
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// db needs to start empty
			assert_eq!(sidechain_db.shards, vec![]);
			sidechain_db.store_blocks(signed_block_vector).unwrap();
		}

		// then
		{
			// open new DB of same path:
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// ensure DB contains previously stored data:
			assert_eq!(*updated_sidechain_db.shards(), vec![shard]);
			let last_block = updated_sidechain_db.last_block_of_shard(&shard).unwrap();
			assert_eq!(last_block.number, signed_block.block().block_number());
			assert_eq!(last_block.hash, signed_block.hash());
			let stored_block_hash =
				updated_sidechain_db.get_block_hash(&shard, last_block.number).unwrap().unwrap();
			assert_eq!(stored_block_hash, signed_block.hash());
			assert_eq!(
				updated_sidechain_db.get_block(&stored_block_hash).unwrap().unwrap(),
				signed_block
			);
		}
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn store_blocks_on_multi_sharding_works() {
		// given
		let path = PathBuf::from("store_blocks_on_multi_sharding_works");
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		let signed_block_one = create_signed_block(20, shard_one);
		let signed_block_two = create_signed_block(1, shard_two);

		let signed_block_vector: Vec<SignedSidechainBlock> =
			vec![signed_block_one.clone(), signed_block_two.clone()];

		// when
		{
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// db needs to start empty
			assert_eq!(sidechain_db.shards, vec![]);
			sidechain_db.store_blocks(signed_block_vector).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn store_mulitple_block_on_one_shard_works() {
		// given
		let path = PathBuf::from("store_mulitple_block_on_one_shard_works");
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(20, shard);
		let signed_block_two = create_signed_block(21, shard);
		let signed_block_vector_one = vec![signed_block_one.clone()];
		let signed_block_vector_two = vec![signed_block_two.clone()];

		// when
		{
			// first iteration
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(signed_block_vector_one).unwrap();
		}
		{
			// second iteration
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(signed_block_vector_two).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn wrong_succession_order_does_not_get_accepted() {
		// given
		let path = PathBuf::from("wrong_succession_order_does_not_get_accepted");
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(7, shard);
		let signed_block_two = create_signed_block(21, shard);
		let signed_block_vector_one = vec![signed_block_one.clone()];
		let signed_block_vector_two = vec![signed_block_two.clone()];

		// when
		{
			// first iteration
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(signed_block_vector_one).unwrap();
		}
		{
			// second iteration
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(signed_block_vector_two).unwrap();
		}
		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			// last block is equal to first block:
			let last_block: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard).unwrap();
			assert_eq!(last_block.number, signed_block_one.block().block_number());

			// storage contains only one blocks:
			// (shard,blocknumber) -> blockhash
			let db_block_hash_one = updated_sidechain_db
				.get_block_hash(&shard, signed_block_one.block().block_number())
				.unwrap()
				.unwrap();
			let db_block_hash_empty = updated_sidechain_db
				.get_block_hash(&shard, signed_block_two.block().block_number())
				.unwrap();
			assert!(db_block_hash_empty.is_none());
			assert_eq!(db_block_hash_one, signed_block_one.hash());
		}
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn get_previous_block_returns_correct_block() {
		// given
		let path = PathBuf::from("get_previous_block_returns_correct_block");
		let shard = H256::from_low_u64_be(1);
		let signed_block_one = create_signed_block(1, shard);
		// create sidechain_db
		{
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![signed_block_one.clone()]).unwrap();
			// create last block one for comparison
			let last_block = LastSidechainBlock {
				hash: signed_block_one.hash(),
				number: signed_block_one.block().block_number(),
			};

			// then
			let some_block = sidechain_db
				.get_previous_block(&shard, signed_block_one.block().block_number() + 1)
				.unwrap();

			// when
			assert_eq!(some_block, last_block);
		}

		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn get_previous_block_returns_none_when_no_block() {
		// given
		let path = PathBuf::from("get_previous_block_returns_none_when_no_block");
		let shard = H256::from_low_u64_be(1);
		// create sidechain_db
		{
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![create_signed_block(1, shard)]).unwrap();

			// then
			let no_block = sidechain_db.get_previous_block(&shard, 1);

			// when
			assert!(no_block.is_none());
		}

		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn purge_shard_works() {
		// given
		let path = PathBuf::from("purge_shard_works");
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		{
			// create sidechain_db
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			// when
			sidechain_db.purge_shard(&shard).unwrap();

			// test if local storage has been cleansed
			assert!(!sidechain_db.shards.contains(&shard));
			assert!(sidechain_db.last_blocks.get(&shard).is_none());
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn purge_shard_from_block_works() {
		// given
		let path = PathBuf::from("purge_shard_from_block_works");
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		let last_block = LastSidechainBlock {
			hash: block_three.hash(),
			number: block_three.block().block_number(),
		};

		{
			// create sidechain_db
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			// when
			sidechain_db.prune_shard_from_block_number(&shard, 2).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn purge_shard_from_block_works_for_last_block() {
		// given
		let path = PathBuf::from("purge_shard_from_block_works_for_last_block");
		let shard = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard);
		let block_two = create_signed_block(2, shard);
		let block_three = create_signed_block(3, shard);
		{
			// create sidechain_db
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![block_one.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_three.clone()]).unwrap();

			// when
			sidechain_db.prune_shard_from_block_number(&shard, 3).unwrap();

			// test if local storage has been cleansed
			assert!(!sidechain_db.shards.contains(&shard));
			assert!(sidechain_db.last_blocks.get(&shard).is_none());
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn prune_shards_works_for_multiple_shards() {
		// given
		let path = PathBuf::from("prune_shards_works_for_multiple_shards");
		// shard one
		let shard_one = H256::from_low_u64_be(1);
		let block_one = create_signed_block(1, shard_one);
		let block_two = create_signed_block(2, shard_one);
		let block_three = create_signed_block(3, shard_one);
		let last_block_one = LastSidechainBlock {
			hash: block_three.hash(),
			number: block_three.block().block_number(),
		};
		// shard two
		let shard_two = H256::from_low_u64_be(2);
		let block_one_s = create_signed_block(1, shard_two);
		let block_two_s = create_signed_block(2, shard_two);
		let block_three_s = create_signed_block(3, shard_two);
		let block_four_s = create_signed_block(4, shard_two);
		let last_block_two = LastSidechainBlock {
			hash: block_four_s.hash(),
			number: block_four_s.block().block_number(),
		};
		{
			// create sidechain_db
			let mut sidechain_db = SidechainStorage::new(path.clone()).unwrap();
			sidechain_db.store_blocks(vec![block_one.clone(), block_one_s.clone()]).unwrap();
			sidechain_db.store_blocks(vec![block_two.clone(), block_two_s.clone()]).unwrap();
			sidechain_db
				.store_blocks(vec![block_three.clone(), block_three_s.clone()])
				.unwrap();
			sidechain_db.store_blocks(vec![block_four_s.clone()]).unwrap();

			// when
			sidechain_db.prune_shards(2);
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path.clone()).unwrap();
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
		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	fn create_signed_block(block_number: u64, shard: ShardIdentifier) -> SignedSidechainBlock {
		let signer_pair = ed25519::Pair::from_string("//Alice", None).unwrap();
		let author: AccountId32 = signer_pair.public().into();
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];

		let block = Block::new(
			author,
			block_number,
			parent_hash,
			layer_one_head,
			shard,
			signed_top_hashes,
			encrypted_payload,
			SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
		);
		block.sign_block(&signer_pair)
	}
}
