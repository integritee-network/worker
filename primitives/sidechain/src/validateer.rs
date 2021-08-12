use crate::error::{Error, Result};
use frame_support::ensure;
use pallet_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;
use substratee_get_storage_verified::GetStorageVerified;
use substratee_node_primitives::Enclave;

pub trait ValidateerFetch {
	fn current_validateers<Header: HeaderT<Hash = H256>>(
		&self,
		latest_header: &Header,
	) -> Result<Vec<Enclave>>;
	fn validateer_count<Header: HeaderT<Hash = H256>>(&self, latest_header: &Header)
		-> Result<u64>;
}

impl<OnchainStorage: GetStorageVerified> ValidateerFetch for OnchainStorage {
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
			.get_multiple_storages_verified(hashes, header)?
			.into_iter()
			.filter_map(|e| e.into_tuple().1)
			.collect();
		ensure!(
			enclaves.len() == count as usize,
			Error::Other("Found less validateers onchain than validateer count")
		);
		Ok(enclaves)
	}

	fn validateer_count<Header: HeaderT<Hash = H256>>(&self, header: &Header) -> Result<u64> {
		self.get_storage_verified(TeeRexStorage::enclave_count(), header)?
			.into_tuple()
			.1
			.ok_or(Error::Other("Could not get validateer count from chain"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use sp_runtime::{generic::Header as HeaderG, traits::BlakeTwo256};
	use std::string::ToString;
	use test_utils::mock::onchain_mock::{validateer_set, OnchainMock};

	pub type Header = HeaderG<u64, BlakeTwo256>;

	pub fn default_header() -> Header {
		Header::new(
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
			Default::default(),
		)
	}

	#[test]
	pub fn get_validateer_count_works() {
		let mock = OnchainMock::default().with_validateer_set();
		assert_eq!(mock.validateer_count(&default_header()).unwrap(), 4u64);
	}

	#[test]
	pub fn get_validateer_set_works() {
		let mock = OnchainMock::default().with_validateer_set();

		let validateers = validateer_set()
			.into_iter()
			.map(|e| e.into_tuple().1.unwrap())
			.collect::<Vec<Enclave>>();

		assert_eq!(mock.current_validateers(&default_header()).unwrap(), validateers);
	}

	#[test]
	pub fn if_validateer_count_bigger_than_returned_validateers_return_err() {
		let mut mock = OnchainMock::default().with_validateer_set();
		mock.insert(TeeRexStorage::enclave_count(), 5u64.encode());

		assert_eq!(
			mock.current_validateers(&default_header()).unwrap_err().to_string(),
			"Found less validateers onchain than validateer count".to_string()
		);
	}
}
