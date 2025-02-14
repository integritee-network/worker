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

use crate::{
	error::Result, pallet_balances::BalancesCallIndexes,
	pallet_enclave_bridge::EnclaveBridgeCallIndexes, pallet_proxy::ProxyCallIndexes,
	pallet_sidechain::SidechainCallIndexes, pallet_teerex::TeerexCallIndexes,
	pallet_timestamp::TimestampCallIndexes,
};
use codec::{Decode, Encode};

use crate::pallet_assets::{ForeignAssetsCallIndexes, NativeAssetsCallIndexes};
use itp_api_client_types::Metadata;

impl TryFrom<NodeMetadataMock> for Metadata {
	type Error = ();

	fn try_from(_: NodeMetadataMock) -> core::result::Result<Self, Self::Error> {
		Err(())
	}
}

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct NodeMetadataMock {
	teerex_module: u8,
	register_sgx_enclave: u8,
	unregister_sovereign_enclave: u8,
	unregister_proxied_enclave: u8,
	register_quoting_enclave: u8,
	register_tcb_info: u8,
	enclave_bridge_module: u8,
	invoke: u8,
	confirm_processed_parentchain_block: u8,
	shield_funds: u8,
	unshield_funds: u8,
	publish_hash: u8,
	update_shard_config: u8,
	sidechain_module: u8,
	imported_sidechain_block: u8,
	proxy_module: u8,
	add_proxy: u8,
	proxy: u8,
	balances_module: u8,
	transfer: u8,
	transfer_keep_alive: u8,
	transfer_allow_death: u8,
	timestamp_module: u8,
	timestamp_set: u8,
	foreign_assets_module: u8,
	foreign_assets_transfer: u8,
	foreign_assets_transfer_keep_alive: u8,
	foreign_assets_transfer_all: u8,
	native_assets_module: u8,
	native_assets_transfer: u8,
	native_assets_transfer_keep_alive: u8,
	native_assets_transfer_all: u8,
	runtime_spec_version: u32,
	runtime_transaction_version: u32,
}

impl NodeMetadataMock {
	pub fn new() -> Self {
		NodeMetadataMock {
			teerex_module: 50u8,
			register_sgx_enclave: 0u8,
			unregister_sovereign_enclave: 1u8,
			unregister_proxied_enclave: 2u8,
			register_quoting_enclave: 3,
			register_tcb_info: 4,
			enclave_bridge_module: 54u8,
			invoke: 0u8,
			confirm_processed_parentchain_block: 1u8,
			shield_funds: 2u8,
			unshield_funds: 3u8,
			publish_hash: 4u8,
			update_shard_config: 5u8,
			sidechain_module: 53u8,
			imported_sidechain_block: 0u8,
			proxy_module: 7u8,
			add_proxy: 1u8,
			proxy: 0u8,
			balances_module: 10u8,
			transfer: 7u8,
			transfer_keep_alive: 3u8,
			transfer_allow_death: 0u8,
			timestamp_module: 3,
			timestamp_set: 0,
			foreign_assets_module: 53,
			foreign_assets_transfer: 8,
			foreign_assets_transfer_keep_alive: 9,
			foreign_assets_transfer_all: 32,
			native_assets_module: 50,
			native_assets_transfer: 8,
			native_assets_transfer_keep_alive: 9,
			native_assets_transfer_all: 32,
			runtime_spec_version: 25,
			runtime_transaction_version: 4,
		}
	}
}

impl TeerexCallIndexes for NodeMetadataMock {
	fn register_sgx_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_sgx_enclave])
	}

	fn unregister_sovereign_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unregister_sovereign_enclave])
	}

	fn unregister_proxied_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unregister_proxied_enclave])
	}

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_quoting_enclave])
	}

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_tcb_info])
	}
}

impl EnclaveBridgeCallIndexes for NodeMetadataMock {
	fn invoke_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.invoke])
	}

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.confirm_processed_parentchain_block])
	}

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.shield_funds])
	}

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.unshield_funds])
	}

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.publish_hash])
	}

	fn update_shard_config_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.enclave_bridge_module, self.update_shard_config])
	}
}

impl SidechainCallIndexes for NodeMetadataMock {
	fn confirm_imported_sidechain_block_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.sidechain_module, self.imported_sidechain_block])
	}
}

impl ProxyCallIndexes for NodeMetadataMock {
	fn add_proxy_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.proxy_module, self.add_proxy])
	}

	fn proxy_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.proxy_module, self.proxy])
	}
}

impl BalancesCallIndexes for NodeMetadataMock {
	fn transfer_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.balances_module, self.transfer])
	}

	fn transfer_keep_alive_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.balances_module, self.transfer_keep_alive])
	}

	fn transfer_allow_death_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.balances_module, self.transfer_allow_death])
	}
}

impl ForeignAssetsCallIndexes for NodeMetadataMock {
	fn foreign_assets_transfer_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.foreign_assets_module, self.foreign_assets_transfer])
	}

	fn foreign_assets_transfer_keep_alive_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.foreign_assets_module, self.foreign_assets_transfer_keep_alive])
	}

	fn foreign_assets_transfer_all_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.foreign_assets_module, self.foreign_assets_transfer_all])
	}
}

impl NativeAssetsCallIndexes for NodeMetadataMock {
	fn native_assets_transfer_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.native_assets_module, self.native_assets_transfer])
	}

	fn native_assets_transfer_keep_alive_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.native_assets_module, self.native_assets_transfer_keep_alive])
	}

	fn native_assets_transfer_all_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.native_assets_module, self.native_assets_transfer_all])
	}
}
impl TimestampCallIndexes for NodeMetadataMock {
	fn timestamp_set_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.timestamp_module, self.timestamp_set])
	}
}
