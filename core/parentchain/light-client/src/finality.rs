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

//! Finality for determination of the light client validation.

use crate::{
	error::Result,
	grandpa_log,
	justification::GrandpaJustification,
	state::{RelayState, ScheduledChangeAtBlock},
	AuthorityList, Error, NumberFor,
};
use finality_grandpa::voter_set::VoterSet;
use log::*;
pub use sp_finality_grandpa::SetId;
use sp_finality_grandpa::{AuthorityId, ScheduledChange, GRANDPA_ENGINE_ID};
use sp_runtime::{
	generic::Digest,
	traits::{Block as ParentchainBlockTrait, Header as HeaderTrait},
	EncodedJustification, Justifications,
};

#[derive(Default)]
pub struct GrandpaFinality;

#[derive(Default)]
pub struct ParachainFinality;

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

impl<Block> Finality<Block> for ParachainFinality
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

impl<Block> Finality<Block> for GrandpaFinality
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
		Self::apply_validator_set_change(relay, &header);

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
					justification,
					block_hash,
					block_num,
					validator_set_id,
					&voter_set,
				) {
					// FIXME: Printing error upon invalid justification, but this will need a better fix
					// see issue #353
					error!("Block {:?} contained invalid justification: {:?}", block_num, err);
					relay.unjustified_headers.push(block_hash);
					relay.set_last_finalized_block_header(header);
					return Err(err)
				}
				Self::schedule_validator_set_change(relay, &header);

				Ok(())
			},
			None => {
				relay.unjustified_headers.push(block_hash);
				relay.set_last_finalized_block_header(header);

				debug!(
					"Syncing finalized block without grandpa proof. Amount of unjustified headers: {}",
					relay.unjustified_headers.len()
				);
				Err(Error::NoJustificationFound)
			},
		}
	}
}

impl GrandpaFinality {
	fn apply_validator_set_change<Block: ParentchainBlockTrait>(
		relay: &mut RelayState<Block>,
		header: &Block::Header,
	) {
		if let Some(change) = relay.scheduled_change.take() {
			if &change.at_block == header.number() {
				relay.current_validator_set = change.next_authority_list;
				relay.current_validator_set_id += 1;
			}
		}
	}

	fn schedule_validator_set_change<Block: ParentchainBlockTrait>(
		relay: &mut RelayState<Block>,
		header: &Block::Header,
	) {
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

	fn verify_grandpa_proof<Block: ParentchainBlockTrait>(
		encoded_justification: EncodedJustification,
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
			&encoded_justification,
			(hash, number),
			set_id,
			voters,
		)?;

		Ok(())
	}
}

fn pending_change<Block: ParentchainBlockTrait>(
	digest: &Digest,
) -> Option<ScheduledChange<NumberFor<Block>>> {
	grandpa_log::<Block>(digest).and_then(|log| log.try_into_change())
}
