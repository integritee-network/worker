use crate::{ocall::ocall_api::EnclaveOnChainOCallApi, Result};
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::prelude::Vec;
use substratee_storage::{verify_storage_entries, StorageEntryVerified};
use substratee_worker_primitives::WorkerRequest;

pub trait GetOnchainStorage {
	fn get_onchain_storage<H: Header<Hash = H256>>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<Vec<u8>>>>;
}

impl<O: EnclaveOnChainOCallApi> GetOnchainStorage for O {
	fn get_onchain_storage<H: Header<Hash = H256>>(
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
