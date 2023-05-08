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

use crate::error::{Error, Result};
use frame_support::ensure;
use itp_ocall_api::EnclaveOnChainOCallApi;
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

impl<OnchainStorage: EnclaveOnChainOCallApi> ValidateerFetch for OnchainStorage {
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
			.ok_or_else(|| Error::Other("Could not get validateer count from chain"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::Encode;
	use itc_parentchain_test::ParentchainHeaderBuilder;
	use itp_test::mock::onchain_mock::{validateer_set, OnchainMock};
	use std::string::ToString;

	#[test]
	pub fn get_validateer_count_works() {
		let header = ParentchainHeaderBuilder::default().build();
		let mock = OnchainMock::default().add_validateer_set(&header, None);
		assert_eq!(mock.validateer_count(&header).unwrap(), 4u64);
	}

	#[test]
	pub fn get_validateer_set_works() {
		let header = ParentchainHeaderBuilder::default().build();
		let mock = OnchainMock::default().add_validateer_set(&header, None);

		let validateers = validateer_set();

		assert_eq!(mock.current_validateers(&header).unwrap(), validateers);
	}

	#[test]
	pub fn if_validateer_count_bigger_than_returned_validateers_return_err() {
		let header = ParentchainHeaderBuilder::default().build();
		let mut mock = OnchainMock::default().add_validateer_set(&header, None);
		mock.insert_at_header(&header, TeeRexStorage::enclave_count(), 5u64.encode());

		assert_eq!(
			mock.current_validateers(&header).unwrap_err().to_string(),
			"Found less validateers onchain than validateer count".to_string()
		);
	}
}
