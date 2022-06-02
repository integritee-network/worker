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

//! Grandpa Light-client validation crate that verifies parentchain blocks.

use crate::{
	error::Error,
	finality::Finality,
	grandpa_log,
	light_validation_state::LightValidationState,
	state::{RelayState, ScheduledChangeAtBlock},
	AuthorityList, AuthorityListRef, ExtrinsicSender, HashFor, HashingFor, LightClientState,
	NumberFor, RelayId, Validator,
};
use codec::Encode;
use core::iter::Iterator;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::{Error as StorageError, StorageProof, StorageProofChecker};
use log::*;
use sp_finality_grandpa::ScheduledChange;
pub use sp_finality_grandpa::SetId;
use sp_runtime::{
	generic::{Digest, SignedBlock},
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

	fn apply_validator_set_change(relay: &mut RelayState<Block>, header: &Block::Header) {
		if let Some(change) = relay.scheduled_change.take() {
			if &change.at_block == header.number() {
				relay.current_validator_set = change.next_authority_list;
				relay.current_validator_set_id += 1;
			}
		}
	}

	fn schedule_validator_set_change(relay: &mut RelayState<Block>, header: &Block::Header) {
		if let Some(log) = pending_change::<Block>(header.digest()) {
			if relay.scheduled_change.is_some() {
				error!(
					"Tried to scheduled authorities change even though one is already scheduled!!"
				); // should not happen if blockchain is configured properly
			} else {
				relay.scheduled_change = Some(ScheduledChangeAtBlock {
					at_block: log.delay + *header.number(),
					next_authority_list: log.next_authorities,
				})
			}
		}
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
		let mut parent_hash = child.parent_hash();
		if *parent_hash == ancestor_hash {
			return Ok(())
		}

		// If we find that the header's parent hash matches our ancestor's hash we're done
		for header in proof.iter() {
			// Need to check that blocks are actually related
			if header.hash() != *parent_hash {
				break
			}

			parent_hash = header.parent_hash();
			if *parent_hash == ancestor_hash {
				return Ok(())
			}
		}

		Err(Error::InvalidAncestryProof)
	}
}

impl<Block: ParentchainBlockTrait, OCallApi: EnclaveOnChainOCallApi> Validator<Block>
	for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn initialize_relay(
		// nur grandpa
		&mut self,
		block_header: Block::Header,
		validator_set: AuthorityList,
		validator_set_proof: StorageProof,
	) -> Result<RelayId, Error> {
		let state_root = block_header.state_root();
		Self::check_validator_set_proof(state_root, validator_set_proof, &validator_set)?;

		let relay_info = RelayState::new(block_header, validator_set);

		let new_relay_id = self.num_relays() + 1;
		self.light_validation_state.tracked_relays.insert(new_relay_id, relay_info);

		self.light_validation_state.num_relays = new_relay_id;

		Ok(new_relay_id)
	}

	fn submit_finalized_headers(
		&mut self,
		relay_id: RelayId,
		header: Block::Header,
		ancestry_proof: Vec<Block::Header>,
		validator_set: AuthorityList,
		validator_set_id: SetId,
		justifications: Option<Justifications>,
	) -> Result<(), Error> {
		let mut relay = self
			.light_validation_state
			.tracked_relays
			.get_mut(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;

		// Check that the new header is a descendant of the old header
		let last_header = &relay.last_finalized_block_header;
		Self::verify_ancestry(ancestry_proof, last_header.hash(), &header)?;

		let _ = self.finality.validate(
			header.clone(),
			&validator_set,
			validator_set_id,
			justifications,
			relay,
		);

		Self::schedule_validator_set_change(relay, &header);

		// a valid grandpa proof proofs finalization of all previous unjustified blocks
		relay.header_hashes.append(&mut relay.unjustified_headers);
		relay.header_hashes.push(header.hash());

		relay.set_last_finalized_block_header(header);

		if validator_set_id > relay.current_validator_set_id {
			relay.current_validator_set = validator_set;
			relay.current_validator_set_id = validator_set_id;
		}

		Ok(())
	}

	fn submit_block(
		&mut self,
		relay_id: RelayId,
		signed_block: &SignedBlock<Block>,
	) -> Result<(), Error> {
		let header = signed_block.block.header();
		let justifications = signed_block.justifications.clone();

		let relay = self
			.light_validation_state
			.tracked_relays
			.get_mut(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;

		if relay.last_finalized_block_header.hash() != *header.parent_hash() {
			return Err(Error::HeaderAncestryMismatch)
		}
		let ancestry_proof = vec![];

		Self::apply_validator_set_change(relay, header);

		let validator_set = relay.current_validator_set.clone();
		let validator_set_id = relay.current_validator_set_id;
		self.submit_finalized_headers(
			relay_id,
			header.clone(),
			ancestry_proof,
			validator_set,
			validator_set_id,
			justifications,
		)
	}

	fn submit_xt_to_be_included(
		&mut self,
		relay_id: RelayId,
		extrinsic: OpaqueExtrinsic,
	) -> Result<(), Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get_mut(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;
		relay.verify_tx_inclusion.push(extrinsic);
		Ok(())
	}

	fn check_xt_inclusion(&mut self, relay_id: RelayId, block: &Block) -> Result<(), Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get_mut(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;

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

		Ok(())
	}

	fn set_state(&mut self, state: LightValidationState<Block>) {
		self.light_validation_state = state;
	}

	fn get_state(&self) -> &LightValidationState<Block> {
		&self.light_validation_state
	}
}

impl<Block: ParentchainBlockTrait, OCallApi: EnclaveOnChainOCallApi> ExtrinsicSender
	for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn send_extrinsics(&mut self, extrinsics: Vec<OpaqueExtrinsic>) -> Result<(), Error> {
		for xt in extrinsics.iter() {
			self.submit_xt_to_be_included(self.num_relays(), xt.clone()).unwrap();
		}

		self.ocall_api
			.send_to_parentchain(extrinsics)
			.map_err(|e| Error::Other(format!("Failed to send extrinsics: {}", e).into()))
	}
}

impl<Block: ParentchainBlockTrait, OCallApi: EnclaveOnChainOCallApi> LightClientState<Block>
	for LightValidation<Block, OCallApi>
{
	fn num_xt_to_be_included(&mut self, relay_id: RelayId) -> Result<usize, Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;
		Ok(relay.verify_tx_inclusion.len())
	}

	fn genesis_hash(&self, relay_id: RelayId) -> Result<HashFor<Block>, Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;
		Ok(relay.header_hashes[0])
	}

	fn latest_finalized_header(&self, relay_id: RelayId) -> Result<Block::Header, Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;
		Ok(relay.last_finalized_block_header.clone())
	}

	fn penultimate_finalized_block_header(
		&self,
		relay_id: RelayId,
	) -> Result<Block::Header, Error> {
		let relay = self
			.light_validation_state
			.tracked_relays
			.get(&relay_id)
			.ok_or(Error::NoSuchRelayExists)?;
		Ok(relay.penultimate_finalized_block_header.clone())
	}

	fn num_relays(&self) -> RelayId {
		self.light_validation_state.num_relays
	}
}

impl<Block: ParentchainBlockTrait, OCallApi: EnclaveOnChainOCallApi> fmt::Debug
	for LightValidation<Block, OCallApi>
{
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"LightValidation {{ num_relays: {}, tracked_relays: {:?} }}",
			self.light_validation_state.num_relays, self.light_validation_state.tracked_relays
		)
	}
}

pub fn pending_change<Block: ParentchainBlockTrait>(
	digest: &Digest,
) -> Option<ScheduledChange<NumberFor<Block>>> {
	grandpa_log::<Block>(digest).and_then(|log| log.try_into_change())
}
