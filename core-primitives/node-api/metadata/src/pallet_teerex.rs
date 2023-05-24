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
	fn register_ias_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn register_dcap_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn unregister_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]>;

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]>;

	fn call_worker_call_indexes(&self) -> Result<[u8; 2]>;

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]>;

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]>;

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]>;

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]>;
}

pub trait TeerexStorageKey {
	fn enclave_count_storage_key(&self) -> Result<StorageKey>;

	fn enclave_registry_storage_map_key(&self, index: u64) -> Result<StorageKey>;
}

impl TeerexCallIndexes for NodeMetadata {
	fn register_ias_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_ias_enclave")
	}

	fn register_dcap_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_dcap_enclave")
	}

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_quoting_enclave")
	}

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "register_tcb_info")
	}

	fn unregister_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "unregister_enclave")
	}

	fn call_worker_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "call_worker")
	}

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "confirm_processed_parentchain_block")
	}

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "shield_funds")
	}

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "unshield_funds")
	}

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEEREX, "publish_hash")
	}
}

impl TeerexStorageKey for NodeMetadata {
	fn enclave_count_storage_key(&self) -> Result<StorageKey> {
		self.storage_value_key(TEEREX, "EnclaveCount")
	}

	fn enclave_registry_storage_map_key(&self, index: u64) -> Result<StorageKey> {
		self.storage_map_key(TEEREX, "EnclaveRegistry", index)
	}
}
