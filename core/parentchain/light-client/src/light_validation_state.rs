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

//! State of the light-client validation.

use crate::{state::RelayState, Error, HashFor, LightClientState};
use codec::{Decode, Encode};
use sp_runtime::traits::Block as ParentchainBlockTrait;

pub use sp_consensus_grandpa::SetId;

#[derive(Encode, Decode, Clone, Debug, Eq, PartialEq)]
pub struct LightValidationState<Block: ParentchainBlockTrait> {
	pub(crate) relay_state: RelayState<Block>,
}

impl<Block: ParentchainBlockTrait> From<RelayState<Block>> for LightValidationState<Block> {
	fn from(value: RelayState<Block>) -> Self {
		Self::new(value)
	}
}

impl<Block: ParentchainBlockTrait> LightValidationState<Block> {
	pub fn new(relay_state: RelayState<Block>) -> Self {
		Self { relay_state }
	}

	pub(crate) fn get_relay(&self) -> &RelayState<Block> {
		&self.relay_state
	}

	pub(crate) fn get_relay_mut(&mut self) -> &mut RelayState<Block> {
		&mut self.relay_state
	}
}

impl<Block> LightClientState<Block> for LightValidationState<Block>
where
	Block: ParentchainBlockTrait,
{
	fn num_xt_to_be_included(&self) -> Result<usize, Error> {
		let relay = self.get_relay();
		Ok(relay.verify_tx_inclusion.len())
	}

	fn genesis_hash(&self) -> Result<HashFor<Block>, Error> {
		Ok(self.get_relay().genesis_hash)
	}

	fn latest_finalized_header(&self) -> Result<Block::Header, Error> {
		let relay = self.get_relay();
		Ok(relay.last_finalized_block_header.clone())
	}

	fn penultimate_finalized_block_header(&self) -> Result<Block::Header, Error> {
		let relay = self.get_relay();
		Ok(relay.penultimate_finalized_block_header.clone())
	}
}
