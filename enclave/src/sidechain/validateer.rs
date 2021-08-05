use crate::{error::Error, onchain::storage::GetOnchainStorage, Result};
use frame_support::ensure;
use pallet_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;
use substratee_node_primitives::Enclave;

pub trait ValidateerSet {
	fn current_validateers<Header: HeaderT<Hash = H256>>(
		&self,
		latest_header: &Header,
	) -> Result<Vec<Enclave>>;
	fn validateer_count<Header: HeaderT<Hash = H256>>(&self, latest_header: &Header)
		-> Result<u64>;
}

impl<OnchainStorage: GetOnchainStorage> ValidateerSet for OnchainStorage {
	fn current_validateers<Header: HeaderT<Hash = H256>>(
		&self,
		header: &Header,
	) -> Result<Vec<Enclave>> {
		let count = self.validateer_count(header)?;

		let mut hashes = Vec::with_capacity(count as usize);
		for i in 1..=count {
			hashes.push(TeeRexStorage::enclave(i))
		}

		let enclaves: Vec<Enclave> = self
			.get_multiple_onchain_storages(hashes, header)?
			.into_iter()
			.filter_map(|e| e.into_tuple().1)
			.collect();
		ensure!(
			enclaves.len() == count as usize,
			Error::Other("Found less validateers onchain than validateer count".into())
		);
		Ok(enclaves)
	}

	fn validateer_count<Header: HeaderT<Hash = H256>>(&self, header: &Header) -> Result<u64> {
		Ok(self
			.get_onchain_storage(TeeRexStorage::enclave_count(), header)?
			.into_tuple()
			.1
			.ok_or(Error::Other("Could not get validateer count from chain".into()))?)
	}
}

#[cfg(feature = "test")]
pub mod tests {
	use super::*;
	use crate::Header;
	use codec::{Decode, Encode};
	use std::collections::HashMap;
	use substratee_storage::StorageEntryVerified;

	type OnchainMock = HashMap<Vec<u8>, Vec<u8>>;

	pub fn validateer_set() -> Vec<StorageEntryVerified<Enclave>> {
		vec![
			StorageEntryVerified::new(TeeRexStorage::enclave(1), Some(Default::default())),
			StorageEntryVerified::new(TeeRexStorage::enclave(2), Some(Default::default())),
			StorageEntryVerified::new(TeeRexStorage::enclave(3), Some(Default::default())),
			StorageEntryVerified::new(TeeRexStorage::enclave(4), Some(Default::default())),
		]
	}

	pub fn default_header() -> Header {
		Header::new(
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
		)
	}

	impl GetOnchainStorage for OnchainMock {
		fn get_onchain_storage<H: HeaderT<Hash = H256>, V: Decode>(
			&self,
			storage_hash: Vec<u8>,
			_header: &H,
		) -> Result<StorageEntryVerified<V>> {
			let value = self
				.get(&storage_hash)
				.map(|val| Decode::decode(&mut val.as_slice()))
				.transpose()?;

			Ok(StorageEntryVerified::new(storage_hash.clone(), value))
		}

		fn get_multiple_onchain_storages<H: HeaderT<Hash = H256>, V: Decode>(
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

	pub fn get_validateer_count_works() {
		let mut mock = OnchainMock::new();
		mock.insert(TeeRexStorage::enclave_count(), 4u64.encode());

		assert_eq!(mock.validateer_count(&default_header()).unwrap(), 4u64);
	}

	pub fn get_validateer_set_works() {
		let mut mock = OnchainMock::new();
		mock.insert(Default::default(), 4u64.encode());

		for (k, v) in validateer_set().into_iter().map(|e| e.into_tuple()) {
			mock.insert(k, v.map(|v| v.encode()).unwrap());
		}

		let validateers = validateer_set()
			.into_iter()
			.map(|e| e.into_tuple().1.unwrap())
			.collect::<Vec<Enclave>>();

		assert_eq!(mock.current_validateers(&default_header()).unwrap(), validateers);
	}

	pub fn current_validateer_returns_err_if_count_different_from_returned_validateers() {
		let mut mock = OnchainMock::new();
		mock.insert(Default::default(), 4u64.encode());

		assert_eq!(mock.validateer_count(&default_header()).unwrap(), 4u64);

		// assert_eq!(
		// 	OnchainMock.current_validateers(Default::default()).unwrap_err().0,
		// 	"Found less validateers onchain than validateer count".into()
		// );
	}
}
