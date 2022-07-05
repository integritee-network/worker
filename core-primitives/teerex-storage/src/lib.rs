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

#![cfg_attr(not(feature = "std"), no_std)]

use itp_storage::{error::Result, StorageKeyProvider};
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
	fn enclave_count(storage_key_provider: &impl StorageKeyProvider) -> Result<Vec<u8>>;
	fn enclave(index: u64, storage_key_provider: &impl StorageKeyProvider) -> Result<Vec<u8>>;
}

impl<S: StoragePrefix> TeerexStorageKeys for S {
	fn enclave_count(storage_key_provider: &impl StorageKeyProvider) -> Result<Vec<u8>> {
		Ok(storage_key_provider.storage_value_key(Self::prefix(), "EnclaveCount")?.0)
	}

	fn enclave(index: u64, storage_key_provider: &impl StorageKeyProvider) -> Result<Vec<u8>> {
		Ok(storage_key_provider
			.storage_map_key(Self::prefix(), "EnclaveRegistry", &index)?
			.0)
	}
}
