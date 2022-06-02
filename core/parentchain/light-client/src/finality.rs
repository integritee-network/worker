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

/// Finali
use crate::{
	error::Result, justification::GrandpaJustification, state::RelayState, AuthorityList, NumberFor,
};
use finality_grandpa::voter_set::VoterSet;
use log::*;
pub use sp_finality_grandpa::SetId;
use sp_finality_grandpa::{AuthorityId, GRANDPA_ENGINE_ID};
use sp_runtime::{
	traits::{Block as ParentchainBlockTrait, Header as HeaderTrait},
	Justification, Justifications,
};
use std::vec::Vec;

#[derive(Default)]
pub struct Grandpa {
	pub authorities: AuthorityList,
	pub authority_proof: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct Parachain;

pub trait Finality<Block: ParentchainBlockTrait> {
	fn validate(
		&self,
		header: Block::Header,
		validator_set: &AuthorityList,
		validator_set_id: SetId,
		justifications: Option<Justifications>,
		relay: &mut RelayState<Block>,
	) -> Result<()>;
}

impl<Block> Finality<Block> for Parachain
where
	Block: ParentchainBlockTrait,
{
	fn validate(
		&self,
		_header: Block::Header,
		_validator_set: &AuthorityList,
		_validator_set_id: SetId,
		_justifications: Option<Justifications>,
		_relay: &mut RelayState<Block>,
	) -> Result<()> {
		Ok(())
	}
}

impl<Block> Finality<Block> for Grandpa
where
	Block: ParentchainBlockTrait,
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn validate(
		&self,
		header: Block::Header,
		validator_set: &AuthorityList,
		validator_set_id: SetId,
		justifications: Option<Justifications>,
		relay: &mut RelayState<Block>,
	) -> Result<()> {
		// Check that the header has been finalized
		let voter_set =
			VoterSet::new(validator_set.clone().into_iter()).expect("VoterSet may not be empty");

		// ensure justifications is a grandpa justification
		let grandpa_justification =
			justifications.and_then(|just| just.into_justification(GRANDPA_ENGINE_ID));

		let block_hash = header.hash();
		let block_num = *header.number();

		match grandpa_justification {
			Some(justification) => {
				if let Err(err) = Self::verify_grandpa_proof::<Block>(
					(GRANDPA_ENGINE_ID, justification),
					block_hash,
					block_num,
					validator_set_id,
					&voter_set,
				) {
					// FIXME: Printing error upon invalid justification, but this will need a better fix
					// see issue #353
					error!("Block {:?} contained invalid justification: {:?}", block_num, err);
					relay.unjustified_headers.push(header.hash());
					relay.set_last_finalized_block_header(header);
					return Ok(())
				}
			},
			None => {
				relay.unjustified_headers.push(header.hash());
				relay.set_last_finalized_block_header(header);

				debug!(
					"Syncing finalized block without grandpa proof. Amount of unjustified headers: {}",
					relay.unjustified_headers.len()
				);
				return Ok(())
			},
		}
		Ok(())
	}
}

impl Grandpa {
	fn verify_grandpa_proof<Block: ParentchainBlockTrait>(
		justification: Justification,
		hash: Block::Hash,
		number: NumberFor<Block>,
		set_id: u64,
		voters: &VoterSet<AuthorityId>,
	) -> Result<()>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
	{
		// We don't really care about the justification, as long as it's valid
		let _ = GrandpaJustification::<Block>::decode_and_verify_finalizes(
			&justification.1,
			(hash, number),
			set_id,
			voters,
		)?;

		Ok(())
	}
}
