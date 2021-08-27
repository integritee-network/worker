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

use codec::{Decode, Encode};
use log::*;
use my_node_runtime::{Event, Hash, Header, UncheckedExtrinsic};
use sgx_types::*;
use sp_core::{
	crypto::{AccountId32, Ss58Codec},
	sr25519,
	storage::StorageKey,
	Pair, H256,
};
use std::{
	collections::HashMap,
	fs::{self, File},
	io::{stdin, Write},
	path::Path,
	slice, str,
	sync::{
		mpsc::{channel, Sender},
		Mutex,
	},
};
use substratee_node_primitives::{ShardIdentifier, SignedBlock};

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;
use rocksdb::{WriteBatch, DB};
use std::path::PathBuf;
use substratee_worker_primitives::{
	block::{BlockNumber as SidechainBlockNumber, SignedBlock as SignedSidechainBlock},
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait},
};
pub type Result<T> = std::result::Result<T, Error>;

/// key value of sidechain db of last block
const LAST_BLOCK_KEY: &[u8] = b"last_sidechainblock";
/// key value of the stored shards vector
const STORED_SHARDS_KEY: &[u8] = b"stored_shards";

/// Allows to store blocks
#[cfg_attr(test, automock)]
pub trait BlockStorage {
	fn store_blocks(&mut self, blocks: Vec<SignedSidechainBlock>) -> Result<()>;
}

/// DB errors.
#[derive(Debug)]
pub enum Error {
	/// RocksDB Error
	OperationalError(rocksdb::Error),
	/// Blocknumber Succession error
	InvalidBlockNumberSuccession(SignedSidechainBlock),
	/// Last block of shard not found
	LastBlockNotFound(ShardIdentifier),
	/// Decoding Error
	DecodeError,
}

/// Contains the blocknumber and blokhash of the
/// last sidechain block
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug, Default)]
pub struct LastSidechainBlock {
	/// hash of the last sidechain block
	hash: H256,
	/// block number of the last sidechain block
	number: SidechainBlockNumber,
}

/// Struct used to insert newly produced sidechainblocks
/// into the database
pub struct SidechainStorage {
	/// database
	pub db: DB,
	/// shards in database
	pub shards: Vec<ShardIdentifier>,
	/// map to last sidechain block of every shard
	pub last_blocks: HashMap<ShardIdentifier, LastSidechainBlock>,
}

//FIXME: create key functions, such that blocknumer is always in the same format & nothing can get mixed up!
//TODO: create purge_old_blocks function
//TODO: create unit tests for shard purge & purge_oldBlocks function
impl BlockStorage for SidechainStorage {
	/// update sidechain storage
	fn store_blocks(&mut self, blocks_to_store: Vec<SignedSidechainBlock>) -> Result<()> {
		println! {"Received blocks: {:?}", blocks_to_store};
		let mut batch = WriteBatch::default();
		let mut new_shard = false;
		for signed_block in blocks_to_store.clone().into_iter() {
			// check if current block is the next in line
			let current_block_shard = signed_block.block().shard_id();
			let current_block_nr = signed_block.block().block_number();
			if self.shards.contains(&current_block_shard) {
				let last_block: &LastSidechainBlock =
					self.last_blocks.get(&current_block_shard).unwrap();
				if last_block.number != current_block_nr - 1 {
					error!("The to be included sidechainblock number {:?} is not a succession of the previous sidechain block in the db: {:?}",
                    current_block_nr, last_block.number);
					break
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
				LastSidechainBlock { hash: current_block_hash.into(), number: current_block_nr };
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
}

impl SidechainStorage {
	pub fn new(path: PathBuf) -> Result<SidechainStorage> {
		let db = DB::open_default(path).unwrap();
		// get shards in db
		let shards: Vec<ShardIdentifier> = match db.get(STORED_SHARDS_KEY.encode()) {
			Ok(Some(shards)) => Decode::decode(&mut shards.as_slice()).unwrap(),
			Ok(None) => vec![],
			Err(e) => {
				error!("Could not read shards from db: {}", e);
				return Err(Error::OperationalError(e))
			},
		};
		// get last block of each shard
		let mut last_blocks = HashMap::new();
		for shard in shards.iter() {
			match db.get((LAST_BLOCK_KEY, shard).encode()) {
				Ok(Some(last_block_encoded)) => {
					match LastSidechainBlock::decode(&mut last_block_encoded.as_slice()) {
						Ok(last_block) => {
							last_blocks.insert(shard.clone(), last_block);
						},
						Err(e) => {
							error!("Could not decode signed block: {:?}", e);
							return Err(Error::DecodeError)
						},
					}
				},
				Ok(None) => {},
				Err(e) => {
					error!("Could not read shards from db: {}", e);
					return Err(Error::OperationalError(e))
				},
			}
		}
		Ok(SidechainStorage { db, shards, last_blocks })
	}

	/// update sidechain storage from decoded signed blocks
	pub fn update_db_from_encoded(&mut self, mut encoded_signed_blocks: &[u8]) -> Result<()> {
		let signed_blocks: Vec<SignedSidechainBlock> =
			match Decode::decode(&mut encoded_signed_blocks) {
				Ok(blocks) => blocks,
				Err(e) => {
					error!("Could not decode signed blocks: {:?}", e);
					return Err(Error::DecodeError)
				},
			};
		self.store_blocks(signed_blocks)
	}

	/// purges a shard and its block from the db storage
	pub fn purge_shard(&mut self, shard: ShardIdentifier) -> Result<()> {
		// get all shards
		if self.shards.contains(&shard) {
			// remove shard from list
			self.shards.retain(|&x| x != shard);
			//FIXME: Errorhandling
			self.db.put(STORED_SHARDS_KEY.encode(), self.shards.encode()).unwrap();
			// get last block of shard
			let mut last_block: &LastSidechainBlock = match self.last_blocks.get(&shard) {
				Some(last_block) => last_block,
				None => return Err(Error::LastBlockNotFound(shard)),
			};
			// remove last block from storage
			// FIXME: Errorhandling
			self.db.delete(last_block.hash.encode()).unwrap();
			self.db.delete((shard, last_block.number).encode()).unwrap();
			self.db.delete((LAST_BLOCK_KEY, shard).encode()).unwrap();

			//FIXME: Check -> does this make sense? Unit test!
			while (true) {
				match self.get_previous_block(shard, last_block.number) {
					Some(previous_block) => {
						last_block = previous_block;
						// FIXME: Errorhandling
						self.db.delete(last_block.hash.encode()).unwrap();
						self.db.delete((shard, last_block.number).encode()).unwrap();
					},
					None => break,
				}
			}
		}
		Ok(())
	}

	// gets the previous block in chain of current block
	fn get_previous_block(
		&self,
		shard: ShardIdentifier,
		current_block_number: SidechainBlockNumber,
	) -> Option<&LastSidechainBlock> {
		if let Some(block_hash_encoded) =
			self.db.get((shard, current_block_number).encode()).unwrap()
		{
			let block_hash = H256::decode(&mut block_hash_encoded.as_slice()).unwrap();
			&LastSidechainBlock { hash: block_hash.into(), number: current_block_number - 1 };
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rocksdb::Options;
	use sp_core::{
		crypto::{AccountId32, Pair},
		ed25519, H256,
	};
	use substratee_worker_primitives::block::Block;

	#[test]
	fn sidechain_db_struct_works() {
		// given
		let path = "../bin/_sidechain_db_struct_works";
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		let signed_block_one = create_signed_block(20, shard_one);
		let signed_block_two = create_signed_block(1, shard_two);

		let mut signed_block_vector: Vec<SignedSidechainBlock> = vec![];
		signed_block_vector.push(signed_block_one.clone());
		signed_block_vector.push(signed_block_two.clone());

		// when
		{
			let mut sidechain_db = SidechainStorage::new(path).unwrap();
			// db needs to start empty
			assert_eq!(sidechain_db.shards, vec![]);
			sidechain_db.update_db(signed_block_vector).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path).unwrap();
			assert_eq!(updated_sidechain_db.shards[0], shard_one);
			assert_eq!(updated_sidechain_db.shards[1], shard_two);
			let last_block_one: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_one).unwrap();
			let last_block_two: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_two).unwrap();
			assert_eq!(last_block_one.number, 20);
			assert_eq!(last_block_two.number, 1);
			assert_eq!(last_block_one.hash, signed_block_one.hash().into());
			assert_eq!(last_block_two.hash, signed_block_two.hash().into());
		}

		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn update_db_from_encoded_works() {
		// given
		let path = "../bin/_update_db_from_encoded_works";
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		let signed_block_one = create_signed_block(20, shard_one);
		let signed_block_two = create_signed_block(1, shard_two);

		let mut signed_block_vector: Vec<SignedSidechainBlock> = vec![];
		signed_block_vector.push(signed_block_one.clone());
		signed_block_vector.push(signed_block_two.clone());

		// encode blocks to slice [u8]
		let encoded_blocks = signed_block_vector.encode();
		let signed_blocks_slice = unsafe {
			slice::from_raw_parts(encoded_blocks.as_ptr(), encoded_blocks.len() as usize)
		};

		// when
		{
			let mut sidechain_db = SidechainStorage::new(path).unwrap();
			sidechain_db.update_db_from_encoded(signed_blocks_slice).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path).unwrap();
			// shards
			assert_eq!(updated_sidechain_db.shards[0], shard_one);
			assert_eq!(updated_sidechain_db.shards[1], shard_two);
			// last blocks
			let last_block_one: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_one).unwrap();
			let last_block_two: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_two).unwrap();
			assert_eq!(last_block_one.number, 20);
			assert_eq!(last_block_two.number, 1);
			assert_eq!(last_block_one.hash, signed_block_one.hash().into());
			assert_eq!(last_block_two.hash, signed_block_two.hash().into());
			// (shard,blocknumber) -> blockhash
			let db_block_hash_one = H256::decode(
				&mut updated_sidechain_db
					.db
					.get((shard_one, 20 as SidechainBlockNumber).encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_hash_two = H256::decode(
				&mut updated_sidechain_db
					.db
					.get((shard_two, 1 as SidechainBlockNumber).encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			assert_eq!(db_block_hash_one, signed_block_one.hash().into());
			assert_eq!(db_block_hash_two, signed_block_two.hash().into());
			// block hash -> signed block
			let db_block_one = SignedSidechainBlock::decode(
				&mut updated_sidechain_db
					.db
					.get(&last_block_one.hash.encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_two = SignedSidechainBlock::decode(
				&mut updated_sidechain_db
					.db
					.get(&last_block_two.hash.encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			assert_eq!(db_block_one, signed_block_one);
			assert_eq!(db_block_two, signed_block_two);
		}

		// clean up
		let _ = DB::destroy(&Options::default(), path).unwrap();
	}

	#[test]
	fn block_succession_check_works() {
		// given
		let path = "../bin/_block_succession_check_works";
		let shard_one = H256::from_low_u64_be(1);
		let shard_two = H256::from_low_u64_be(2);
		let signed_block_one_one = create_signed_block(20, shard_one);
		let signed_block_one_two = create_signed_block(21, shard_one);
		let signed_block_two_one = create_signed_block(1, shard_two);
		let signed_block_two_two = create_signed_block(3, shard_two);

		let mut signed_block_vector: Vec<SignedSidechainBlock> = vec![];
		signed_block_vector.push(signed_block_one_one.clone());
		signed_block_vector.push(signed_block_two_one.clone());

		let mut signed_block_vector_second: Vec<SignedSidechainBlock> = vec![];
		signed_block_vector_second.push(signed_block_one_two.clone());
		signed_block_vector_second.push(signed_block_two_two.clone());

		// when
		{
			// first iteration
			let mut sidechain_db = SidechainStorage::new(path).unwrap();
			sidechain_db.update_db(signed_block_vector).unwrap();
		}
		{
			// second iteration
			let mut sidechain_db = SidechainStorage::new(path).unwrap();
			sidechain_db.update_db(signed_block_vector_second).unwrap();
		}

		// then
		{
			let updated_sidechain_db = SidechainStorage::new(path).unwrap();
			// shards
			assert_eq!(updated_sidechain_db.shards[0], shard_one);
			assert_eq!(updated_sidechain_db.shards[1], shard_two);
			// last blocks
			let last_block_one: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_one).unwrap();
			let last_block_two: &LastSidechainBlock =
				updated_sidechain_db.last_blocks.get(&shard_two).unwrap();
			assert_eq!(last_block_one.number, 21);
			assert_eq!(last_block_two.number, 1);
			assert_eq!(last_block_one.hash, signed_block_one_two.hash().into());
			assert_eq!(last_block_two.hash, signed_block_two_one.hash().into());
			// (shard,blocknumber) -> blockhash
			let db_block_hash_one_one = H256::decode(
				&mut updated_sidechain_db
					.db
					.get((shard_one, 20 as SidechainBlockNumber).encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_hash_one_two = H256::decode(
				&mut updated_sidechain_db
					.db
					.get((shard_one, 21 as SidechainBlockNumber).encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_hash_two_one = H256::decode(
				&mut updated_sidechain_db
					.db
					.get((shard_two, 1 as SidechainBlockNumber).encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			assert_eq!(db_block_hash_one_one, signed_block_one_one.hash().into());
			assert_eq!(db_block_hash_two_one, signed_block_two_one.hash().into());
			assert_eq!(db_block_hash_one_two, signed_block_one_two.hash().into());
			// ensure block number 3 is empty
			let db_block_hash_empty = updated_sidechain_db
				.db
				.get((shard_two, 3 as SidechainBlockNumber).encode())
				.unwrap();
			assert_eq!(db_block_hash_empty, None);
			// block hash -> signed block
			let db_block_one_one = SignedSidechainBlock::decode(
				&mut updated_sidechain_db
					.db
					.get(&signed_block_one_one.hash().encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_one_two = SignedSidechainBlock::decode(
				&mut updated_sidechain_db
					.db
					.get(&signed_block_one_two.hash().encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			let db_block_two_one = SignedSidechainBlock::decode(
				&mut updated_sidechain_db
					.db
					.get(&signed_block_two_one.hash().encode())
					.unwrap()
					.unwrap()
					.as_slice(),
			)
			.unwrap();
			assert_eq!(db_block_one_one, signed_block_one_one);
			assert_eq!(db_block_one_two, signed_block_one_two);
			assert_eq!(db_block_two_one, signed_block_two_one);
			// ensure block number 3 was not included
			let db_block_empty =
				updated_sidechain_db.db.get(&signed_block_two_two.hash().encode()).unwrap();
			assert_eq!(db_block_empty, None);
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

		let block = Block::construct_block(
			author,
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
		);
		block.sign(&signer_pair)
	}
}
