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

use crate::ConsensusError;
use itp_types::{Block as ParentchainBlock, Header};
use its_consensus_common::{Proposal, Proposer};
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_test::{
	sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait},
	sidechain_block_data_builder::SidechainBlockDataBuilder,
};
use std::time::Duration;

pub struct ProposerMock {
	pub(crate) parentchain_header: Header,
}

impl Proposer<ParentchainBlock, SignedSidechainBlock> for ProposerMock {
	fn propose(
		&self,
		_max_duration: Duration,
	) -> Result<Proposal<SignedSidechainBlock>, ConsensusError> {
		Ok(Proposal {
			block: {
				let block_data = SidechainBlockDataBuilder::random()
					.with_layer_one_head(self.parentchain_header.hash())
					.build();
				SidechainBlockBuilder::random().with_block_data(block_data).build_signed()
			},

			parentchain_effects: Default::default(),
		})
	}
}
