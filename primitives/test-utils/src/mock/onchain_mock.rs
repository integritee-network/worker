use codec::{Decode, Encode};
use pallet_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::*;
use std::collections::HashMap;
use substratee_get_storage_verified::{GetStorageVerified, Result};
use substratee_node_primitives::Enclave;
use substratee_storage::StorageEntryVerified;

#[derive(Default)]
pub struct OnchainMock {
	inner: HashMap<Vec<u8>, Vec<u8>>,
}

impl OnchainMock {
	pub fn with_storage_entries<V: Encode>(
		mut self,
		entries: Vec<StorageEntryVerified<V>>,
	) -> Self {
		for (k, v) in entries.into_iter().map(|e| e.into_tuple()) {
			self.inner.insert(k, v.map(|v| v.encode()).unwrap());
		}
		self
	}

	pub fn with_validateer_set(mut self) -> Self {
		let set = validateer_set();
		self.inner.insert(TeeRexStorage::enclave_count(), (set.len() as u64).encode());
		self.with_storage_entries(set)
	}

	pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
		self.inner.insert(key, value);
	}

	pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
		self.inner.get(key)
	}
}

impl GetStorageVerified for OnchainMock {
	fn get_storage_verified<H: HeaderT<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		_header: &H,
	) -> Result<StorageEntryVerified<V>> {
		let value = self
			.get(&storage_hash)
			.map(|val| Decode::decode(&mut val.as_slice()))
			.transpose()?;

		Ok(StorageEntryVerified::new(storage_hash, value))
	}

	fn get_multiple_storages_verified<H: HeaderT<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		_header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>> {
		let mut entries = Vec::with_capacity(storage_hashes.len());
		for hash in storage_hashes.into_iter() {
			let value =
				self.get(&hash).map(|val| Decode::decode(&mut val.as_slice())).transpose()?;

			entries.push(StorageEntryVerified::new(hash, value))
		}
		Ok(entries)
	}
}

pub fn validateer_set() -> Vec<StorageEntryVerified<Enclave>> {
	vec![
		StorageEntryVerified::new(TeeRexStorage::enclave(1), Some(Default::default())),
		StorageEntryVerified::new(TeeRexStorage::enclave(2), Some(Default::default())),
		StorageEntryVerified::new(TeeRexStorage::enclave(3), Some(Default::default())),
		StorageEntryVerified::new(TeeRexStorage::enclave(4), Some(Default::default())),
	]
}
