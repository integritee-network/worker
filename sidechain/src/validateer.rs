use crate::error::{Error, Result};
use frame_support::ensure;
use itp_storage_verifier::GetStorageVerified;
use itp_teerex_storage::{TeeRexStorage, TeerexStorageKeys};
use itp_types::Enclave;
use sp_core::H256;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;

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
	use itp_test::mock::onchain_mock::{validateer_set, OnchainMock};
	use sp_runtime::{generic::Header as HeaderG, traits::BlakeTwo256};
	use std::string::ToString;

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
		let mock = OnchainMock::default().with_validateer_set(None);
		assert_eq!(mock.validateer_count(&default_header()).unwrap(), 4u64);
	}

	#[test]
	pub fn get_validateer_set_works() {
		let mock = OnchainMock::default().with_validateer_set(None);

		let validateers = validateer_set();

		assert_eq!(mock.current_validateers(&default_header()).unwrap(), validateers);
	}

	#[test]
	pub fn if_validateer_count_bigger_than_returned_validateers_return_err() {
		let mut mock = OnchainMock::default().with_validateer_set(None);
		mock.insert(TeeRexStorage::enclave_count(), 5u64.encode());

		assert_eq!(
			mock.current_validateers(&default_header()).unwrap_err().to_string(),
			"Found less validateers onchain than validateer count".to_string()
		);
	}
}
