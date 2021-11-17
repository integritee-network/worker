#![cfg_attr(not(feature = "std"), no_std)]

//! Basic storage access abstraction

use codec::Decode;
use core::result::Result as StdResult;
use derive_more::{Display, From};
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::{verify_storage_entries, Error as StorageError, StorageEntryVerified};
use itp_types::WorkerRequest;
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::{prelude::*, vec};

/// Very basic abstraction over storage access that returns a `StorageEntryVerified`. This enforces
/// that the implementation of this trait uses the `itp_storage::VerifyStorageProof` trait
/// because a `StorageEntryVerified` instance cannot be created otherwise.
///
/// This is very generic and most-likely one of the innermost traits.
pub trait GetStorageVerified {
	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>>;

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>>;
}

impl<O: EnclaveOnChainOCallApi> GetStorageVerified for O {
	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		Ok(self
			.get_multiple_storages_verified(vec![storage_hash], header)?
			.into_iter()
			.next()
			.ok_or(StorageError::StorageValueUnavailable)?)
	}

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
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

#[derive(Debug, Display, From)]
pub enum Error {
	Storage(StorageError),
	Codec(codec::Error),
	Sgx(sgx_types::sgx_status_t),
}

pub type Result<T> = StdResult<T, Error>;
