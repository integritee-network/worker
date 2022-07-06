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
use sp_std::{prelude::Vec, sync::Arc};

#[cfg(feature = "mocks")]
pub mod mock;

pub struct TeeRexStorage<StorageKeys> {
	storage_key_provider: Arc<StorageKeys>,
}

impl<StorageKeys> TeeRexStorage<StorageKeys> {
	pub fn new(storage_key_provider: Arc<StorageKeys>) -> Self {
		Self { storage_key_provider }
	}
}

pub trait TeeRexStorageAccess {
	type TeerexStorageType: TeeRexStorageKeys;

	fn teerex_storage(&self) -> &Self::TeerexStorageType;
}

// Separate the prefix from the rest because in our case we changed the storage prefix due to
// the rebranding.
pub trait StoragePrefix {
	fn prefix() -> &'static str;
}

impl<StorageKeys> StoragePrefix for TeeRexStorage<StorageKeys> {
	fn prefix() -> &'static str {
		"Teerex"
	}
}

pub trait TeeRexStorageKeys {
	fn enclave_count(&self) -> Result<Vec<u8>>;
	fn enclave(&self, index: u64) -> Result<Vec<u8>>;
}

impl<StorageKeys> TeeRexStorageKeys for TeeRexStorage<StorageKeys>
where
	StorageKeys: StorageKeyProvider,
{
	fn enclave_count(&self) -> Result<Vec<u8>> {
		Ok(self.storage_key_provider.storage_value_key(Self::prefix(), "EnclaveCount")?.0)
	}

	fn enclave(&self, index: u64) -> Result<Vec<u8>> {
		Ok(self
			.storage_key_provider
			.storage_map_key(Self::prefix(), "EnclaveRegistry", &index)?
			.0)
	}
}
