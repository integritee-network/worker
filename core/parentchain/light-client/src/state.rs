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
use sp_finality_grandpa::{AuthorityList, SetId};
use sp_runtime::{
	traits::{Block as BlockT, Header as HeaderT},
	OpaqueExtrinsic,
};
use std::{fmt, vec::Vec};

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct RelayState<Block: BlockT> {
	pub last_finalized_block_header: Block::Header,
	pub penultimate_finalized_block_header: Block::Header,
	pub current_validator_set: AuthorityList,
	pub current_validator_set_id: SetId,
	pub header_hashes: Vec<Block::Hash>,
	pub unjustified_headers: Vec<Block::Hash>, // Finalized headers without grandpa proof
	pub verify_tx_inclusion: Vec<OpaqueExtrinsic>, // Transactions sent by the relay
	pub scheduled_change: Option<ScheduledChangeAtBlock<Block::Header>>, // Scheduled Authorities change as indicated in the header's digest.
}

#[derive(Encode, Decode, Clone, PartialEq)]
pub struct ScheduledChangeAtBlock<Header: HeaderT> {
	pub at_block: Header::Number,
	pub next_authority_list: AuthorityList,
}

impl<Block: BlockT> RelayState<Block> {
	pub fn new(block_header: Block::Header, validator_set: AuthorityList) -> Self {
		RelayState {
			header_hashes: vec![block_header.hash()],
			last_finalized_block_header: block_header.clone(),
			// is it bad to initialize with the same? Header trait does no implement default...
			penultimate_finalized_block_header: block_header,
			current_validator_set: validator_set,
			current_validator_set_id: 0,
			unjustified_headers: Vec::new(),
			verify_tx_inclusion: Vec::new(),
			scheduled_change: None,
		}
	}

	pub fn set_last_finalized_block_header(&mut self, header: Block::Header) {
		self.penultimate_finalized_block_header =
			std::mem::replace(&mut self.last_finalized_block_header, header);
	}
}

impl<Block: BlockT> fmt::Debug for RelayState<Block> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(
			f,
			"RelayInfo {{ last_finalized_block_header_number: {:?}, current_validator_set: {:?}, \
        current_validator_set_id: {} amount of transaction in tx_inclusion_queue: {} }}",
			self.last_finalized_block_header.number(),
			self.current_validator_set,
			self.current_validator_set_id,
			self.verify_tx_inclusion.len()
		)
	}
}
