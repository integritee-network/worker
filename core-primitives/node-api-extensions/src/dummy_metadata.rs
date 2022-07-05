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

use crate::node_metadata_repository::{AccessNodeMetadata, NodeMetadataRepository};
use codec::{Decode, Encode};
use itp_storage::{
	error::Result, key_provider_stub::StorageKeyProviderStub, Error, StorageKey, StorageKeyProvider,
};

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct DummyMetadata {
	pub teerex_module: u8,
	pub register_enclave: u8,
	pub call_worker: u8,
	pub processed_parentchain_block: u8,
	pub shield_funds: u8,
	pub unshield_funds: u8,
	pub sidechain_module: u8,
	pub proposed_sidechain_block: u8,
	pub runtime_spec_version: u32,
	pub runtime_transaction_version: u32,
	storage_key_provider: StorageKeyProviderStub,
}

impl DummyMetadata {
	pub fn new() -> Self {
		DummyMetadata {
			teerex_module: 50u8,
			register_enclave: 0u8,
			call_worker: 2u8,
			processed_parentchain_block: 3u8,
			shield_funds: 4u8,
			unshield_funds: 5u8,
			sidechain_module: 53u8,
			proposed_sidechain_block: 0u8,
			runtime_spec_version: 24,
			runtime_transaction_version: 3,
			storage_key_provider: StorageKeyProviderStub {},
		}
	}
}

impl StorageKeyProvider for NodeMetadataRepository {
	fn storage_map_key<K: Encode>(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
		map_key: K,
	) -> Result<StorageKey> {
		self.get_from_metadata(|m| {
			m.storage_key_provider
				.storage_map_key(storage_prefix, storage_key_name, map_key)
		})
		.map_err(|e| Error::Other(e.into()))?
	}

	fn storage_value_key(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
	) -> Result<StorageKey> {
		self.get_from_metadata(|m| {
			m.storage_key_provider.storage_value_key(storage_prefix, storage_key_name)
		})
		.map_err(|e| Error::Other(e.into()))?
	}

	fn storage_double_map_key<K: Encode, Q: Encode>(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
		first: K,
		second: Q,
	) -> Result<StorageKey> {
		self.get_from_metadata(|m| {
			m.storage_key_provider.storage_double_map_key(
				storage_prefix,
				storage_key_name,
				first,
				second,
			)
		})
		.map_err(|e| Error::Other(e.into()))?
	}
}
