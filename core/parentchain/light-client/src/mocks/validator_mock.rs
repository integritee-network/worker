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
	error::Result, AuthorityList, ExtrinsicSender, HashFor, LightClientState, LightValidationState,
	RelayId, Validator,
};
use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
use itp_storage::StorageProof;
use itp_types::Block;
use sp_runtime::{generic::SignedBlock, traits::Block as BlockT, OpaqueExtrinsic};
use std::vec::Vec;

type Header = <Block as BlockT>::Header;

/// Validator mock to be used in tests.
#[derive(Clone, Debug, Default)]
pub struct ValidatorMock {
	light_validation_state: LightValidationState<Block>,
}

impl Validator<Block> for ValidatorMock {
	fn initialize_grandpa_relay(
		&mut self,
		_block_header: Header,
		_validator_set: AuthorityList,
		_validator_set_proof: StorageProof,
	) -> Result<RelayId> {
		todo!()
	}

	fn initialize_parachain_relay(
		&mut self,
		_block_header: Header,
		_validator_set: AuthorityList,
	) -> Result<RelayId> {
		todo!()
	}

	fn submit_block(
		&mut self,
		_relay_id: RelayId,
		_signed_block: &SignedBlock<Block>,
	) -> Result<()> {
		Ok(())
	}

	fn check_xt_inclusion(&mut self, _relay_id: RelayId, _block: &Block) -> Result<()> {
		Ok(())
	}

	fn set_state(&mut self, state: LightValidationState<Block>) {
		self.light_validation_state = state;
	}

	fn get_state(&self) -> &LightValidationState<Block> {
		&self.light_validation_state
	}
}

impl ExtrinsicSender for ValidatorMock {
	fn send_extrinsics(&mut self, _extrinsics: Vec<OpaqueExtrinsic>) -> Result<()> {
		Ok(())
	}
}

impl LightClientState<Block> for ValidatorMock {
	fn num_xt_to_be_included(&self, _relay_id: RelayId) -> Result<usize> {
		todo!()
	}

	fn genesis_hash(&self, _relay_id: RelayId) -> Result<HashFor<Block>> {
		todo!()
	}

	fn latest_finalized_header(&self, _relay_id: RelayId) -> Result<Header> {
		Ok(ParentchainHeaderBuilder::default().build())
	}

	fn penultimate_finalized_block_header(&self, _relay_id: RelayId) -> Result<Header> {
		Ok(ParentchainHeaderBuilder::default().build())
	}

	fn num_relays(&self) -> RelayId {
		0
	}
}
