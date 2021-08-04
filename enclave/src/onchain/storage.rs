use crate::{ocall::ocall_api::EnclaveOnChainOCallApi, Result};
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::prelude::Vec;
use substratee_storage::{verify_storage_entries, Error as StorageError, StorageEntryVerified};
use substratee_worker_primitives::WorkerRequest;

pub trait GetOnchainStorage {
	fn get_onchain_storage<H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<Vec<u8>>>;

	fn get_multiple_onchain_storages<H: Header<Hash = H256>>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<Vec<u8>>>>;
}

impl<O: EnclaveOnChainOCallApi> GetOnchainStorage for O {
	fn get_onchain_storage<H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<Vec<u8>>> {
		// the code below seems like an overkill, but it is surprisingly difficult to
		// get an owned value from a `Vec` without cloning.
		Ok(self
			.get_multiple_onchain_storages(vec![storage_hash], header)?
			.into_iter()
			.nth(0)
			.ok_or(StorageError::StorageValueUnavailable)?)
	}

	fn get_multiple_onchain_storages<H: Header<Hash = H256>>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<Vec<u8>>>> {
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
