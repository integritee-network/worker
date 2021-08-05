#![cfg_attr(not(feature = "std"), no_std)]

//! Abstraction over onchain-storage access, which returns storage values after the
//! storage proof has been checked.

use codec::Decode;
use core::result::Result as StdResult;
use derive_more::{Display, From};
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::prelude::*;
use substratee_ocall_api::EnclaveOnChainOCallApi;
use substratee_storage::{verify_storage_entries, Error as StorageError, StorageEntryVerified};
use substratee_worker_primitives::WorkerRequest;

#[derive(Debug, Display, From)]
pub enum Error {
	Storage(StorageError),
	Codec(codec::Error),
	Sgx(sgx_types::sgx_status_t),
}

pub type Result<T> = StdResult<T, Error>;

pub trait GetOnchainStorage {
	fn get_onchain_storage<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>>;

	fn get_multiple_onchain_storages<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>>;
}

impl<O: EnclaveOnChainOCallApi> GetOnchainStorage for O {
	fn get_onchain_storage<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		Ok(self
			.get_multiple_onchain_storages(vec![storage_hash], header)?
			.into_iter()
			.next()
			.ok_or(StorageError::StorageValueUnavailable)?)
	}

	fn get_multiple_onchain_storages<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>> {
		let requests = storage_hashes
			.into_iter()
			.map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
			.collect();

		let storage_entries = self
			.worker_request::<Vec<u8>>(requests)
			.map(|storages| verify_storage_entries(storages, header))??;

		Ok(storage_entries)
	}
}
