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
use crate::{error::Result, NodeMetadata};
use sp_core::storage::StorageKey;

/// Pallet' name:
const TEEREX: &str = "Teerex";

pub trait TeerexCallIndexes {
	fn register_sgx_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn unregister_sovereign_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn unregister_proxied_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]>;
}

pub trait TeerexStorageKey {
	fn sovereign_enclaves_storage_map_key(&self, index: u64) -> Result<StorageKey>;

	fn proxied_enclaves_storage_map_key(&self, index: u64) -> Result<StorageKey>;
}

impl TeerexCallIndexes for NodeMetadata {
	fn register_sgx_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_sgx_enclave")
	}

	fn unregister_sovereign_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "unregister_sovereign_enclave")
	}

	fn unregister_proxied_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "unregister_proxied_enclave")
	}

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_quoting_enclave")
	}

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_tcb_info")
	}
}

impl TeerexStorageKey for NodeMetadata {
	fn sovereign_enclaves_storage_map_key(&self, index: u64) -> Result<StorageKey> {
		self.storage_map_key(TEEREX, "SovereignEnclaves", index)
	}
	fn proxied_enclaves_storage_map_key(&self, index: u64) -> Result<StorageKey> {
		self.storage_map_key(TEEREX, "ProxiedEnclaves", index)
	}
}
