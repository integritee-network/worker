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
	AuthorityListRef, ExtrinsicSender, HashFor, HashingFor, LightClientState, NumberFor, Validator,
};
use codec::Encode;
use core::iter::Iterator;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::{Error as StorageError, StorageProof, StorageProofChecker};
use itp_types::parentchain::{IdentifyParentchain, ParentchainId};
use sp_runtime::{
	generic::SignedBlock,
	traits::{Block as ParentchainBlockTrait, Header as HeaderTrait},
	Justifications, OpaqueExtrinsic,
};
use std::{boxed::Box, fmt, sync::Arc, vec::Vec};

#[derive(Clone)]
pub struct LightValidation<Block: ParentchainBlockTrait, OcallApi> {
	light_validation_state: LightValidationState<Block>,
	ocall_api: Arc<OcallApi>,
	parentchain_id: ParentchainId,
	finality: Arc<Box<dyn Finality<Block> + Sync + Send + 'static>>,
}

impl<Block: ParentchainBlockTrait, OcallApi> IdentifyParentchain
	for LightValidation<Block, OcallApi>
{
	fn parentchain_id(&self) -> ParentchainId {
		self.parentchain_id
	}
}

impl<Block: ParentchainBlockTrait, OcallApi: EnclaveOnChainOCallApi>
	LightValidation<Block, OcallApi>
{
	pub fn new(
		ocall_api: Arc<OcallApi>,
		finality: Arc<Box<dyn Finality<Block> + Sync + Send + 'static>>,
		light_validation_state: LightValidationState<Block>,
		parentchain_id: ParentchainId,
	) -> Self {
		Self { light_validation_state, ocall_api, finality, parentchain_id }
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
		header: Block::Header,
		ancestry_proof: Vec<Block::Header>,
		justifications: Option<Justifications>,
	) -> Result<(), Error> {
		let relay = self.light_validation_state.get_relay_mut();

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

		// Todo: Justifying the headers here is actually wrong, but it prevents an ever-growing
		// `unjustified_headers` queue because in the parachain case we won't have justifications,
		// and in solo chain setups we only get a justification upon an Grandpa authority change.
		// Hence, we justify the headers here until we properly solve this in #1404.
		relay.justify_headers();
		relay.push_header_hash(header.hash());

		relay.set_last_finalized_block_header(header);

		if validator_set_id > relay.current_validator_set_id {
			relay.current_validator_set = validator_set;
			relay.current_validator_set_id = validator_set_id;
		}

		Ok(())
	}
}

impl<Block, OCallApi> Validator<Block> for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn submit_block(&mut self, signed_block: &SignedBlock<Block>) -> Result<(), Error> {
		let header = signed_block.block.header();
		let justifications = signed_block.justifications.clone();

		let relay = self.light_validation_state.get_relay_mut();

		if relay.last_finalized_block_header.hash() != *header.parent_hash() {
			return Err(Error::HeaderAncestryMismatch)
		}

		self.submit_finalized_headers(header.clone(), vec![], justifications)
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
		self.ocall_api
			.send_to_parentchain(extrinsics, &self.parentchain_id)
			.map_err(|e| {
				Error::Other(
					format!("[{:?}] Failed to send extrinsics: {}", self.parentchain_id, e).into(),
				)
			})
	}
}

impl<Block, OCallApi> LightClientState<Block> for LightValidation<Block, OCallApi>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
	Block: ParentchainBlockTrait,
	OCallApi: EnclaveOnChainOCallApi,
{
	fn genesis_hash(&self) -> Result<HashFor<Block>, Error> {
		self.light_validation_state.genesis_hash()
	}

	fn latest_finalized_header(&self) -> Result<Block::Header, Error> {
		self.light_validation_state.latest_finalized_header()
	}

	fn penultimate_finalized_block_header(&self) -> Result<Block::Header, Error> {
		self.light_validation_state.penultimate_finalized_block_header()
	}
}

impl<Block: ParentchainBlockTrait, OCallApi> fmt::Debug for LightValidation<Block, OCallApi> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"LightValidation {{ parentchain_id: {:?}, relay_state: {:?} }}",
			self.parentchain_id, self.light_validation_state.relay_state
		)
	}
}

pub fn check_validator_set_proof<Block: ParentchainBlockTrait>(
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
