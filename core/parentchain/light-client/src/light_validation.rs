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

//! Light-client validation crate that verifies parentchain blocks.

use crate::{
	error::Error, finality::Finality, light_validation_state::LightValidationState,
	state::RelayState, AuthorityList, AuthorityListRef, ExtrinsicSender, HashFor, HashingFor,
	LightClientState, NumberFor, RelayId, Validator,
};
use codec::Encode;
use core::iter::Iterator;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::{Error as StorageError, StorageProof, StorageProofChecker};
use log::*;
use sp_runtime::{
	generic::SignedBlock,
	traits::{Block as ParentchainBlockTrait, Hash as HashTrait, Header as HeaderTrait},
	Justifications, OpaqueExtrinsic,
};
use std::{boxed::Box, fmt, sync::Arc, vec::Vec};

#[derive(Clone)]
pub struct LightValidation<Block: ParentchainBlockTrait, OcallApi: EnclaveOnChainOCallApi> {
	light_validation_state: LightValidationState<Block>,
	ocall_api: Arc<OcallApi>,
	finality: Arc<Box<dyn Finality<Block> + Sync + Send + 'static>>,
}

impl<Block: ParentchainBlockTrait, OcallApi: EnclaveOnChainOCallApi>
	LightValidation<Block, OcallApi>
{
	pub fn new(
		ocall_api: Arc<OcallApi>,
		finality: Arc<Box<dyn Finality<Block> + Sync + Send + 'static>>,
	) -> Self {
		Self { light_validation_state: LightValidationState::new(), ocall_api, finality }
	}

	fn initialize_relay(
		&mut self,
		block_header: Block::Header,
		validator_set: AuthorityList,
	) -> Result<RelayId, Error> {
		let relay_info = RelayState::new(block_header, validator_set);

		let new_relay_id = self.light_validation_state.num_relays + 1;
		self.light_validation_state.tracked_relays.insert(new_relay_id, relay_info);

		self.light_validation_state.num_relays = new_relay_id;

		Ok(new_relay_id)
	}

	fn check_validator_set_proof(
		state_root: &HashFor<Block>,
		proof: StorageProof,
		validator_set: AuthorityListRef,
	) -> Result<(), Error> {
		let checker = StorageProofChecker::<HashingFor<Block>>::new(*state_root, proof)?;

		// By encoding the given set we should have an easy way to compare
		// with the stuff we get out of storage via `read_value`
		let mut encoded_validator_set = validator_set.encode();
		encoded_validator_set.insert(0, 1); // Add AUTHORITIES_VERISON == 1
		let actual_validator_set = checker
			.read_value(b":grandpa_authorities")?
			.ok_or(StorageError::StorageValueUnavailable)?;

		if encoded_validator_set == actual_validator_set {
			Ok(())
		} else {
			Err(Error::ValidatorSetMismatch)
		}
	}

	// A naive way to check whether a `child` header is a descendant
	// of an `ancestor` header. For this it requires a proof which
	// is a chain of headers between (but not including) the `child`
	// and `ancestor`. This could be updated to use something like
	// Log2 Ancestors (#2053) in the future.
	fn verify_ancestry(
		proof: Vec<Block::Header>,
		ancestor_hash: HashFor<Block>,
		child: &Block::Header,
	) -> Result<(), Error> {
		let parent_hash = child.parent_hash();
		if *parent_hash == ancestor_hash {
			return Ok(())
		}

		// Find the header's parent hash that matches our ancestor's hash
		match proof
			.iter()
			.find(|header| header.hash() == *parent_hash && *header.parent_hash() == ancestor_hash)
		{
			Some(_) => Ok(()),
			None => Err(Error::InvalidAncestryProof),
		}
	}

	fn submit_finalized_headers(
		&mut self,
		relay_id: RelayId,
		header: Block::Header,
		ancestry_proof: Vec<Block::Header>,
		justifications: Option<Justifications>,
	) -> Result<(), Error> {
		let relay = self.light_validation_state.get_tracked_relay_mut(relay_id)?;

		let validator_set = relay.current_validator_set.clone();
		let validator_set_id = relay.current_validator_set_id;

		// Check that the new header is a descendant of the old header
		let last_header = &relay.last_finalized_block_header;
		Self::verify_ancestry(ancestry_proof, last_header.hash(), &header)?;

		if let Err(e) = self.finality.validate(
			header.clone(),
			&validator_set,
			validator_set_id,
			justifications,
			relay,
		) {
			match e {
				Error::NoJustificationFound => return Ok(()),
				_ => return Err(e),
			}
		}

		// A valid grandpa proof proves finalization of all previous unjustified blocks.
		relay.header_hashes.append(&mut relay.unjustified_headers);
		relay.header_hashes.push(header.hash());

		relay.set_last_finalized_block_header(header);

		if validator_set_id > relay.current_validator_set_id {
			relay.current_validator_set = validator_set;
			relay.current_validator_set_id = validator_set_id;
		}

		Ok(())
	}

	fn submit_xt_to_be_included(
		&mut self,
		relay_id: RelayId,
		extrinsic: OpaqueExtrinsic,
	) -> Result<(), Error> {
		let relay = self.light_validation_state.get_tracked_relay_mut(relay_id)?;
		relay.verify_tx_inclusion.push(extrinsic);

		debug!(
			"{} extrinsics in cache, waiting for inclusion verification",
			relay.verify_tx_inclusion.len()
		);

		Ok(())
	}
}

impl<Block, OCallApi> Validator<Block> for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn initialize_grandpa_relay(
		&mut self,
		block_header: Block::Header,
		validator_set: AuthorityList,
		validator_set_proof: StorageProof,
	) -> Result<RelayId, Error> {
		let state_root = block_header.state_root();
		Self::check_validator_set_proof(state_root, validator_set_proof, &validator_set)?;

		self.initialize_relay(block_header, validator_set)
	}

	fn initialize_parachain_relay(
		&mut self,
		block_header: Block::Header,
		validator_set: AuthorityList,
	) -> Result<RelayId, Error> {
		self.initialize_relay(block_header, validator_set)
	}

	fn submit_block(
		&mut self,
		relay_id: RelayId,
		signed_block: &SignedBlock<Block>,
	) -> Result<(), Error> {
		let header = signed_block.block.header();
		let justifications = signed_block.justifications.clone();

		let relay = self.light_validation_state.get_tracked_relay_mut(relay_id)?;

		if relay.last_finalized_block_header.hash() != *header.parent_hash() {
			return Err(Error::HeaderAncestryMismatch)
		}

		self.submit_finalized_headers(relay_id, header.clone(), vec![], justifications)
	}

	fn check_xt_inclusion(&mut self, relay_id: RelayId, block: &Block) -> Result<(), Error> {
		let relay = self.light_validation_state.get_tracked_relay_mut(relay_id)?;

		if relay.verify_tx_inclusion.is_empty() {
			return Ok(())
		}

		let mut found_xts = vec![];
		block.extrinsics().iter().for_each(|xt| {
			if let Some(index) = relay.verify_tx_inclusion.iter().position(|xt_opaque| {
				<HashingFor<Block>>::hash_of(xt) == <HashingFor<Block>>::hash_of(xt_opaque)
			}) {
				found_xts.push(index);
			}
		});

		// sort highest index first
		found_xts.sort_by(|a, b| b.cmp(a));

		let rm: Vec<OpaqueExtrinsic> =
			found_xts.into_iter().map(|i| relay.verify_tx_inclusion.remove(i)).collect();

		if !rm.is_empty() {
			info!("Verified inclusion proof of {} extrinsics.", rm.len());
		}
		debug!(
			"{} extrinsics remaining in cache, waiting for inclusion verification",
			relay.verify_tx_inclusion.len()
		);

		Ok(())
	}

	fn set_state(&mut self, state: LightValidationState<Block>) {
		self.light_validation_state = state;
	}

	fn get_state(&self) -> &LightValidationState<Block> {
		&self.light_validation_state
	}
}

impl<Block, OCallApi> ExtrinsicSender for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn send_extrinsics(&mut self, extrinsics: Vec<OpaqueExtrinsic>) -> Result<(), Error> {
		for xt in extrinsics.iter() {
			self.submit_xt_to_be_included(self.num_relays(), xt.clone()).expect("No Relays");
		}

		self.ocall_api
			.send_to_parentchain(extrinsics)
			.map_err(|e| Error::Other(format!("Failed to send extrinsics: {}", e).into()))
	}
}

impl<Block, OCallApi> LightClientState<Block> for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn num_xt_to_be_included(&self, relay_id: RelayId) -> Result<usize, Error> {
		let relay = self.light_validation_state.get_tracked_relay(relay_id)?;
		Ok(relay.verify_tx_inclusion.len())
	}

	fn genesis_hash(&self, relay_id: RelayId) -> Result<HashFor<Block>, Error> {
		let relay = self.light_validation_state.get_tracked_relay(relay_id)?;
		Ok(relay.header_hashes[0])
	}

	fn latest_finalized_header(&self, relay_id: RelayId) -> Result<Block::Header, Error> {
		let relay = self.light_validation_state.get_tracked_relay(relay_id)?;
		Ok(relay.last_finalized_block_header.clone())
	}

	fn penultimate_finalized_block_header(
		&self,
		relay_id: RelayId,
	) -> Result<Block::Header, Error> {
		let relay = self.light_validation_state.get_tracked_relay(relay_id)?;
		Ok(relay.penultimate_finalized_block_header.clone())
	}

	fn num_relays(&self) -> RelayId {
		self.light_validation_state.num_relays
	}
}

impl<Block, OCallApi> fmt::Debug for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"LightValidation {{ num_relays: {}, tracked_relays: {:?} }}",
			self.light_validation_state.num_relays, self.light_validation_state.tracked_relays
		)
	}
}
