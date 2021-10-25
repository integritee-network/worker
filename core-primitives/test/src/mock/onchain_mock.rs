/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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
use itp_storage::StorageEntryVerified;
use itp_storage_verifier::{GetStorageVerified, Result};
use itp_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use itp_types::Enclave;
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::*;
use std::collections::HashMap;

#[derive(Default)]
pub struct OnchainMock {
	inner: HashMap<Vec<u8>, Vec<u8>>,
}

impl OnchainMock {
	pub fn with_storage_entries<V: Encode>(mut self, entries: Vec<(Vec<u8>, V)>) -> Self {
		for (k, v) in entries.into_iter() {
			self.inner.insert(k, v.encode());
		}
		self
	}

	pub fn with_validateer_set(mut self, set: Option<Vec<Enclave>>) -> Self {
		let set = set.unwrap_or_else(validateer_set);
		self.inner.insert(TeeRexStorage::enclave_count(), (set.len() as u64).encode());
		self.with_storage_entries(into_key_value_storage(set))
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

pub fn validateer_set() -> Vec<Enclave> {
	vec![Default::default(), Default::default(), Default::default(), Default::default()]
}

fn into_key_value_storage(validateers: Vec<Enclave>) -> Vec<(Vec<u8>, Enclave)> {
	validateers
		.into_iter()
		.enumerate()
		.map(|(i, e)| (TeeRexStorage::enclave(i as u64 + 1), e))
		.collect()
}
