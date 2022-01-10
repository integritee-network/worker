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

use crate::{verifier::AuraVerifier, Aura};
use itc_parentchain_block_import_dispatcher::trigger_parentchain_block_import_mock::TriggerParentchainBlockImportMock;
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::{AccountId, Block as ParentchainBlock, Enclave, Header};
use its_consensus_common::{Environment, Error as ConsensusError, Proposal, Proposer};
use its_primitives::{
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedBlockTrait},
	types::block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
};
use its_state::LastBlockExt;
use its_test::sidechain_block_builder::SidechainBlockBuilder;
use sp_runtime::{app_crypto::ed25519, generic::SignedBlock, traits::Header as HeaderTrait};
use std::time::Duration;

pub const SLOT_DURATION: Duration = Duration::from_millis(300);

type AuthorityPair = ed25519::Pair;
pub struct EnvironmentMock;
pub struct ProposerMock {
	parentchain_header: Header,
}

pub type ShardIdentifierFor<SidechainBlock> =
	<<SidechainBlock as SignedBlockTrait>::Block as SidechainBlockTrait>::ShardIdentifier;

pub struct StateMock<SidechainBlock: SidechainBlockTrait> {
	pub last_block: Option<SidechainBlock>,
}

pub type TestAura = Aura<
	AuthorityPair,
	ParentchainBlock,
	SignedSidechainBlock,
	EnvironmentMock,
	OnchainMock,
	TriggerParentchainBlockImportMock<SignedBlock<ParentchainBlock>>,
>;

pub type TestAuraVerifier = AuraVerifier<
	AuthorityPair,
	ParentchainBlock,
	SignedSidechainBlock,
	StateMock<SidechainBlock>,
	OnchainMock,
>;

impl Environment<ParentchainBlock, SignedSidechainBlock> for EnvironmentMock {
	type Proposer = ProposerMock;
	type Error = ConsensusError;

	fn init(
		&mut self,
		header: Header,
		_: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(ProposerMock { parentchain_header: header })
	}
}

impl Proposer<ParentchainBlock, SignedSidechainBlock> for ProposerMock {
	fn propose(
		&self,
		_max_duration: Duration,
	) -> Result<Proposal<SignedSidechainBlock>, ConsensusError> {
		Ok(Proposal {
			block: SidechainBlockBuilder::random()
				.with_parentchain_block_hash(self.parentchain_header.hash())
				.build_signed(),

			parentchain_effects: Default::default(),
		})
	}
}

impl<SidechainBlock: SidechainBlockTrait> LastBlockExt<SidechainBlock>
	for StateMock<SidechainBlock>
{
	fn get_last_block(&self) -> Option<SidechainBlock> {
		self.last_block.clone()
	}

	fn set_last_block(&mut self, block: &SidechainBlock) {
		self.last_block = Some(block.clone())
	}
}

pub fn validateer(account: AccountId) -> Enclave {
	Enclave::new(account, Default::default(), Default::default(), Default::default())
}

pub fn default_header() -> Header {
	Header::new(
		Default::default(),
		Default::default(),
		Default::default(),
		Default::default(),
		Default::default(),
	)
}
