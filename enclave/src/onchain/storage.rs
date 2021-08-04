use crate::{error::Error, ocall::ocall_api::EnclaveOnChainOCallApi, Result};
use codec::Decode;
use sp_core::H256;
use sp_runtime::traits::Header;
use sp_std::{fmt::Debug, prelude::Vec};
use substratee_storage::{verify_storage_entries, Error as StorageError, StorageEntryVerified};
use substratee_worker_primitives::WorkerRequest;

pub trait GetOnchainStorage {
	fn get_onchain_storage_value<V: Decode, H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<Option<V>>;

	fn get_multiple_onchain_storage_values<V: Decode + Debug, H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<Option<V>>>;

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
	fn get_onchain_storage_value<V: Decode, H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<Option<V>> {
		Ok(self
			.get_onchain_storage(storage_hash, header)?
			.into_tuple()
			.1
			.map(|value| Decode::decode(&mut value.as_slice()))
			.transpose()?)
	}

	fn get_multiple_onchain_storage_values<V: Decode + Debug, H: Header<Hash = H256>>(
		&self,
		storage_hash: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<Option<V>>> {
		let (storages, errors): (Vec<_>, Vec<_>) = self
			.get_multiple_onchain_storages(storage_hash, header)?
			.into_iter()
			.map(|entry| entry.into_tuple().1)
			.map(|opt| {
				opt.map(|value| Decode::decode(&mut value.as_slice()).map_err(|e| e.into()))
					.transpose()
			})
			.partition(Result::is_ok);

		for e in errors.into_iter() {
			log::error!("Storage fetch errors: {:?}", e.unwrap_err())
		}

		Ok(storages.into_iter().map(Result::unwrap).collect())
	}

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
