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

use frame_support::sp_runtime::traits::Block as ParentchainBlockTrait;
use itc_parentchain_light_client::light_client_init_params::{
	LightClientInitParams,
	LightClientInitParams::{Grandpa, Parachain},
};
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain, EnclaveResult};
use itp_settings::worker::MR_ENCLAVE_SIZE;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_core::ed25519;
use sp_runtime::traits::Header;

/// mock for EnclaveBase - use in tests
pub struct EnclaveMock;

impl EnclaveBase for EnclaveMock {
	fn init(&self, _mu_ra_url: &str, _untrusted_url: &str) -> EnclaveResult<()> {
		Ok(())
	}

	fn init_enclave_sidechain_components(&self) -> EnclaveResult<()> {
		Ok(())
	}

	fn init_direct_invocation_server(&self, _rpc_server_addr: String) -> EnclaveResult<()> {
		unreachable!()
	}

	fn init_parentchain_components<SpHeader: Header>(
		&self,
		params: LightClientInitParams<SpHeader>,
	) -> EnclaveResult<SpHeader> {
		return match params {
			Grandpa { genesis_header, .. } => Ok(genesis_header),
			Parachain { genesis_header, .. } => Ok(genesis_header),
		}
	}

	fn init_shard(&self, _shard: Vec<u8>) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn trigger_parentchain_block_import(&self) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn set_nonce(&self, _: u32) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn set_node_metadata(&self, _metadata: Vec<u8>) -> EnclaveResult<()> {
		todo!()
	}

	fn get_rsa_shielding_pubkey(&self) -> EnclaveResult<Rsa3072PubKey> {
		unreachable!()
	}

	fn get_ecc_signing_pubkey(&self) -> EnclaveResult<ed25519::Public> {
		unreachable!()
	}

	fn get_mrenclave(&self) -> EnclaveResult<[u8; MR_ENCLAVE_SIZE]> {
		Ok([1u8; MR_ENCLAVE_SIZE])
	}
}

impl Sidechain for EnclaveMock {
	fn sync_parentchain<ParentchainBlock: ParentchainBlockTrait>(
		&self,
		_blocks: &[sp_runtime::generic::SignedBlock<ParentchainBlock>],
		_nonce: u32,
	) -> EnclaveResult<()> {
		Ok(())
	}

	fn execute_trusted_calls(&self) -> EnclaveResult<()> {
		todo!()
	}
}
