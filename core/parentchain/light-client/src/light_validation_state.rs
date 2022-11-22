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

use crate::{state::RelayState, Error, RelayId};
use codec::{Decode, Encode};
pub use sp_finality_grandpa::SetId;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::collections::BTreeMap;

#[derive(Encode, Decode, Clone, Debug)]
pub struct LightValidationState<Block: ParentchainBlockTrait> {
	pub num_relays: RelayId,
	pub tracked_relays: BTreeMap<RelayId, RelayState<Block>>,
}

impl<Block: ParentchainBlockTrait> LightValidationState<Block> {
	pub fn new() -> Self {
		Self { num_relays: Default::default(), tracked_relays: Default::default() }
	}

	pub(crate) fn get_tracked_relay(&self, relay_id: RelayId) -> Result<&RelayState<Block>, Error> {
		let relay = self.tracked_relays.get(&relay_id).ok_or(Error::NoSuchRelayExists)?;
		Ok(relay)
	}

	pub(crate) fn get_tracked_relay_mut(
		&mut self,
		relay_id: RelayId,
	) -> Result<&mut RelayState<Block>, Error> {
		let relay = self.tracked_relays.get_mut(&relay_id).ok_or(Error::NoSuchRelayExists)?;
		Ok(relay)
	}
}

impl<Block: ParentchainBlockTrait> Default for LightValidationState<Block> {
	fn default() -> Self {
		Self { num_relays: Default::default(), tracked_relays: Default::default() }
	}
}
