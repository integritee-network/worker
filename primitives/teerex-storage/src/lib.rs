#![cfg_attr(not(feature = "std"), no_std)]

use itp_storage::{storage_map_key, storage_value_key, StorageHasher};
use sp_std::prelude::Vec;

pub struct TeeRexStorage;

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding. With the below implementation of the `TeerexStorageKeys`, we could simply
// define another struct `OtherStorage`, implement `StoragePrefix` for it, and get the
// `TeerexStorageKeys` implementation for free.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

impl StoragePrefix for TeeRexStorage {
	fn prefix() -> &'static str {
		"Teerex"
	}
}

pub trait TeerexStorageKeys {
	fn enclave_count() -> Vec<u8>;
	fn enclave(index: u64) -> Vec<u8>;
}

impl<S: StoragePrefix> TeerexStorageKeys for S {
	fn enclave_count() -> Vec<u8> {
		storage_value_key(Self::prefix(), "EnclaveCount")
	}

	fn enclave(index: u64) -> Vec<u8> {
		storage_map_key(Self::prefix(), "EnclaveRegistry", &index, &StorageHasher::Blake2_128Concat)
	}
}
