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

use crate::{error::Result, AuthorityList, HashFor, LightClientState, RelayId, SetId, Validator};
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::StorageProof;
use itp_types::Block;
use sp_runtime::{traits::Block as BlockT, Justifications, OpaqueExtrinsic};
use std::vec::Vec;

type Header = <Block as BlockT>::Header;

/// Validator mock to be used in tests.
#[derive(Clone, Copy, Debug)]
pub struct ValidatorMock;

impl Validator<Block> for ValidatorMock {
	fn initialize_relay(
		&mut self,
		_block_header: Header,
		_validator_set: AuthorityList,
		_validator_set_proof: StorageProof,
	) -> Result<RelayId> {
		todo!()
	}

	fn submit_finalized_headers(
		&mut self,
		_relay_id: RelayId,
		_header: Header,
		_ancestry_proof: Vec<Header>,
		_validator_set: AuthorityList,
		_validator_set_id: SetId,
		_justifications: Option<Justifications>,
	) -> Result<()> {
		todo!()
	}

	fn submit_simple_header(
		&mut self,
		_relay_id: RelayId,
		_header: Header,
		_justifications: Option<Justifications>,
	) -> Result<()> {
		todo!()
	}

	fn submit_xt_to_be_included(
		&mut self,
		_relay_id: RelayId,
		_extrinsic: OpaqueExtrinsic,
	) -> Result<()> {
		todo!()
	}

	fn send_extrinsics<OCallApi: EnclaveOnChainOCallApi>(
		&mut self,
		_ocall_api: &OCallApi,
		_extrinsics: Vec<OpaqueExtrinsic>,
	) -> Result<()> {
		todo!()
	}

	fn check_xt_inclusion(&mut self, _relay_id: RelayId, _block: &Block) -> Result<()> {
		todo!()
	}
}

impl LightClientState<Block> for ValidatorMock {
	fn num_xt_to_be_included(&mut self, _relay_id: RelayId) -> Result<usize> {
		todo!()
	}

	fn genesis_hash(&self, _relay_id: RelayId) -> Result<HashFor<Block>> {
		todo!()
	}

	fn latest_finalized_header(&self, _relay_id: RelayId) -> Result<Header> {
		todo!()
	}

	fn penultimate_finalized_block_header(&self, _relay_id: RelayId) -> Result<Header> {
		todo!()
	}

	fn num_relays(&self) -> RelayId {
		todo!()
	}
}
