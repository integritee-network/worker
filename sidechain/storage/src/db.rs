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

use super::{Error, Result};
use codec::{Decode, Encode};
use rocksdb::{WriteBatch, DB};
use std::path::PathBuf;

/// Sidechain DB Storage structure:
/// STORED_SHARDS_KEY -> Vec<(Shard)>
/// (LAST_BLOCK_KEY, Shard) -> (Blockhash, BlockNr) (look up current blockchain state)
/// (Shard , Block number) -> Blockhash (needed for block pruning)
/// Blockhash -> Signed Block (actual block storage)

/// Interface struct to rocks DB
pub struct SidechainDB {
	db: DB,
}

impl SidechainDB {
	pub fn open_default(path: PathBuf) -> Result<SidechainDB> {
		Ok(SidechainDB { db: DB::open_default(path)? })
	}

	/// returns the decoded value of the DB entry, if there is one
	pub fn get<K: Encode, V: Decode>(&self, key: K) -> Result<Option<V>> {
		match self.db.get(key.encode())? {
			None => Ok(None),
			Some(encoded_hash) => Ok(Some(V::decode(&mut encoded_hash.as_slice())?)),
		}
	}

	/// writes a batch to the DB
	pub fn write(&mut self, batch: WriteBatch) -> Result<()> {
		self.db.write(batch).map_err(Error::Operational)
	}

	/// adds a given key value pair to the batch
	pub fn add_to_batch<K: Encode, V: Encode>(batch: &mut WriteBatch, key: K, value: V) {
		batch.put(key.encode(), &value.encode())
	}

	/// adds a delte key command to the batch
	pub fn delete_to_batch<K: Encode>(batch: &mut WriteBatch, key: K) {
		batch.delete(key.encode())
	}

	/// add an entry to the DB
	#[cfg(test)]
	pub fn put<K: Encode, V: Encode>(&mut self, key: K, value: V) -> Result<()> {
		self.db.put(key.encode(), value.encode()).map_err(Error::Operational)
	}
}
