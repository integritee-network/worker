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

//! Logic for checking Substrate storage proofs.

use crate::error::Error;
use hash_db::EMPTY_PREFIX;
use sp_core::Hasher;
use sp_std::vec::Vec;
use sp_trie::{trie_types::TrieDB, HashDBT, MemoryDB, Trie, TrieDBBuilder};

pub type StorageProof = Vec<Vec<u8>>;

/// This struct is used to read storage values from a subset of a Merklized database. The "proof"
/// is a subset of the nodes in the Merkle structure of the database, so that it provides
/// authentication against a known Merkle root as well as the values in the database themselves.
pub struct StorageProofChecker<H: Hasher> {
	root: H::Out,
	db: MemoryDB<H>,
}

impl<H: Hasher> StorageProofChecker<H> {
	/// Constructs a new storage proof checker.
	///
	/// This returns an error if the given proof is invalid with respect to the given root.
	pub fn new(root: H::Out, proof: StorageProof) -> Result<Self, Error> {
		let mut db = MemoryDB::default();
		for item in proof {
			db.insert(EMPTY_PREFIX, &item);
		}
		let checker = StorageProofChecker { root, db };
		// Return error if trie would be invalid.
		let _ = checker.trie()?;
		Ok(checker)
	}

	/// Reads a value from the available subset of storage. If the value cannot be read due to an
	/// incomplete or otherwise invalid proof, this returns an error.
	pub fn read_value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
		self.trie()?
			.get(key)
			.map(|value| value.map(|value| value.to_vec()))
			.map_err(|_| Error::StorageValueUnavailable)
	}

	fn trie(&self) -> Result<TrieDB<H>, Error> {
		if !self.db.contains(&self.root, EMPTY_PREFIX) {
			Err(Error::StorageRootMismatch)
		} else {
			Ok(TrieDBBuilder::new(&self.db, &self.root).build())
		}
	}

	pub fn check_proof(
		root: H::Out,
		storage_key: &[u8],
		proof: StorageProof,
	) -> Result<Option<Vec<u8>>, Error> {
		let storage_checker = StorageProofChecker::<H>::new(root, proof)?;

		storage_checker.read_value(storage_key)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use sp_core::{Blake2Hasher, H256};
	use sp_state_machine::{backend::Backend, new_in_mem, prove_read};
	use sp_trie::HashKey;

	#[test]
	fn storage_proof_check() {
		// construct storage proof
		let mut backend = new_in_mem::<Blake2Hasher, HashKey<Blake2Hasher>>();
		backend.insert(
			vec![
				(None, vec![(b"key1".to_vec(), Some(b"value1".to_vec()))]),
				(None, vec![(b"key2".to_vec(), Some(b"value2".to_vec()))]),
				(None, vec![(b"key3".to_vec(), Some(b"value3".to_vec()))]),
				// Value is too big to fit in a branch node
				(None, vec![(b"key11".to_vec(), Some(vec![0u8; 32]))]),
			],
			Default::default(),
		);
		let root = backend.storage_root(std::iter::empty(), Default::default()).0;
		let proof: StorageProof = prove_read(backend, &[&b"key1"[..], &b"key2"[..], &b"key22"[..]])
			.unwrap()
			.iter_nodes()
			.cloned()
			.collect();

		// check proof in runtime
		let checker = <StorageProofChecker<Blake2Hasher>>::new(root, proof.clone()).unwrap();
		assert_eq!(checker.read_value(b"key1"), Ok(Some(b"value1".to_vec())));
		assert_eq!(checker.read_value(b"key2"), Ok(Some(b"value2".to_vec())));
		assert_eq!(checker.read_value(b"key11111"), Err(Error::StorageValueUnavailable));
		assert_eq!(checker.read_value(b"key22"), Ok(None));

		// checking proof against invalid commitment fails
		assert_eq!(
			<StorageProofChecker<Blake2Hasher>>::new(H256::random(), proof).err(),
			Some(Error::StorageRootMismatch)
		);
	}
}
