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
	error::Result, pallet_sidechain::SidechainCallIndexes, pallet_teerex::TeerexCallIndexes,
};
use codec::{Decode, Encode};

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
	register_ias_enclave: u8,
	register_dcap_enclave: u8,
	unregister_enclave: u8,
	register_quoting_enclave: u8,
	register_tcb_info: u8,
	call_worker: u8,
	processed_parentchain_block: u8,
	shield_funds: u8,
	unshield_funds: u8,
	publish_hash: u8,
	sidechain_module: u8,
	imported_sidechain_block: u8,
	runtime_spec_version: u32,
	runtime_transaction_version: u32,
}

impl NodeMetadataMock {
	pub fn new() -> Self {
		NodeMetadataMock {
			teerex_module: 50u8,
			register_ias_enclave: 0u8,
			register_dcap_enclave: 6,
			unregister_enclave: 1u8,
			register_quoting_enclave: 7,
			register_tcb_info: 8,
			call_worker: 2u8,
			processed_parentchain_block: 3u8,
			shield_funds: 4u8,
			unshield_funds: 5u8,
			publish_hash: 9u8,
			sidechain_module: 53u8,
			imported_sidechain_block: 0u8,
			runtime_spec_version: 25,
			runtime_transaction_version: 4,
		}
	}
}

impl TeerexCallIndexes for NodeMetadataMock {
	fn register_ias_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_ias_enclave])
	}

	fn register_dcap_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_dcap_enclave])
	}

	fn unregister_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unregister_enclave])
	}

	fn register_quoting_enclave_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_quoting_enclave])
	}

	fn register_tcb_info_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.register_tcb_info])
	}

	fn call_worker_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.call_worker])
	}

	fn confirm_processed_parentchain_block_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.processed_parentchain_block])
	}

	fn shield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.shield_funds])
	}

	fn unshield_funds_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unshield_funds])
	}

	fn publish_hash_call_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.teerex_module, self.unshield_funds])
	}
}

impl SidechainCallIndexes for NodeMetadataMock {
	fn confirm_imported_sidechain_block_indexes(&self) -> Result<[u8; 2]> {
		Ok([self.sidechain_module, self.imported_sidechain_block])
	}
}
