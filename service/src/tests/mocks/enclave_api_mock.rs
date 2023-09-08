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

use codec::{Decode, Encode};
use core::fmt::Debug;
use enclave_bridge_primitives::EnclaveFingerprint;
use frame_support::sp_runtime::traits::Block as ParentchainBlockTrait;
use itc_parentchain::primitives::{
	ParentchainId, ParentchainInitParams,
	ParentchainInitParams::{Parachain, Solochain},
};
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain, EnclaveResult};
use itp_settings::worker::MR_ENCLAVE_SIZE;
use itp_storage::StorageProof;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_core::ed25519;

/// mock for EnclaveBase - use in tests
pub struct EnclaveMock;

impl EnclaveBase for EnclaveMock {
	fn init(&self, _mu_ra_url: &str, _untrusted_url: &str, _base_dir: &str) -> EnclaveResult<()> {
		Ok(())
	}

	fn init_enclave_sidechain_components(&self) -> EnclaveResult<()> {
		Ok(())
	}

	fn init_direct_invocation_server(&self, _rpc_server_addr: String) -> EnclaveResult<()> {
		unreachable!()
	}

	fn init_parentchain_components<Header: Debug + Decode>(
		&self,
		params: ParentchainInitParams,
	) -> EnclaveResult<Header> {
		let genesis_header_encoded = match params {
			Solochain { params, .. } => params.genesis_header.encode(),
			Parachain { params, .. } => params.genesis_header.encode(),
		};
		let header = Header::decode(&mut genesis_header_encoded.as_slice())?;
		Ok(header)
	}

	fn init_shard(&self, _shard: Vec<u8>) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn trigger_parentchain_block_import(&self, _: &ParentchainId) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn set_nonce(&self, _: u32, _: ParentchainId) -> EnclaveResult<()> {
		unimplemented!()
	}

	fn set_node_metadata(&self, _metadata: Vec<u8>, _: ParentchainId) -> EnclaveResult<()> {
		todo!()
	}

	fn get_rsa_shielding_pubkey(&self) -> EnclaveResult<Rsa3072PubKey> {
		unreachable!()
	}

	fn get_ecc_signing_pubkey(&self) -> EnclaveResult<ed25519::Public> {
		unreachable!()
	}

	fn get_fingerprint(&self) -> EnclaveResult<EnclaveFingerprint> {
		Ok([1u8; MR_ENCLAVE_SIZE].into())
	}
}

impl Sidechain for EnclaveMock {
	fn sync_parentchain<ParentchainBlock: ParentchainBlockTrait>(
		&self,
		_blocks: &[sp_runtime::generic::SignedBlock<ParentchainBlock>],
		_events: &[Vec<u8>],
		_events_proofs: &[StorageProof],
		_: &ParentchainId,
	) -> EnclaveResult<()> {
		Ok(())
	}

	fn execute_trusted_calls(&self) -> EnclaveResult<()> {
		todo!()
	}
}
