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
use itp_types::ShardIdentifier;
use sp_core::storage::StorageKey;

/// Pallet' name:
pub const ENCLAVE_BRIDGE: &str = "EnclaveBridge";

pub trait EnclaveBridgeCallIndexes {
	fn invoke_call_indexes(&self) -> Result<[u8; 2]>;

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]>;

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]>;

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]>;

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]>;

	fn update_shard_config_call_indexes(&self) -> Result<[u8; 2]>;
}

pub trait EnclaveBridgeStorageKey {
	fn shard_status_storage_map_key(&self, shard: &ShardIdentifier) -> Result<StorageKey>;
	fn shard_config_registry_storage_map_key(&self, shard: &ShardIdentifier) -> Result<StorageKey>;
}

impl EnclaveBridgeCallIndexes for NodeMetadata {
	fn invoke_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "invoke")
	}

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "confirm_processed_parentchain_block")
	}

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "shield_funds")
	}

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "unshield_funds")
	}

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "publish_hash")
	}

	fn update_shard_config_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(ENCLAVE_BRIDGE, "update_shard_config")
	}
}

impl EnclaveBridgeStorageKey for NodeMetadata {
	fn shard_status_storage_map_key(&self, shard: &ShardIdentifier) -> Result<StorageKey> {
		self.storage_map_key(ENCLAVE_BRIDGE, "ShardStatus", shard)
	}
	fn shard_config_registry_storage_map_key(&self, shard: &ShardIdentifier) -> Result<StorageKey> {
		self.storage_map_key(ENCLAVE_BRIDGE, "ShardConfigRegistry", shard)
	}
}
