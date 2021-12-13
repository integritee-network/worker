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
use itp_time_utils::duration_now;
use itp_types::{AccountId, Block as ParentchainBlock, Enclave, Header};
use its_consensus_common::{Environment, Error as ConsensusError, Proposal, Proposer};
use its_primitives::{
	traits::{Block as SidechainBlockT, SignBlock as SignBlockT, SignedBlock as SignedBlockT},
	types::block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
};
use its_state::LastBlockExt;
use sp_core::Pair;
use sp_keyring::ed25519::Keyring;
use sp_runtime::{
	app_crypto::ed25519, generic::SignedBlock, testing::H256, traits::Header as HeaderT,
};
use std::time::Duration;

pub const SLOT_DURATION: Duration = Duration::from_millis(300);

type AuthorityPair = ed25519::Pair;
pub struct EnvironmentMock;
pub struct ProposerMock {
	parentchain_header: Header,
}

pub type ShardIdentifierFor<SB> = <<SB as SignedBlockT>::Block as SidechainBlockT>::ShardIdentifier;

pub struct StateMock<SB: SidechainBlockT> {
	pub last_block: Option<SB>,
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
			block: TestBlockBuilder::new()
				.with_timestamp(duration_now().as_millis() as u64)
				.with_parentchain_head(self.parentchain_header.hash())
				.with_parent_hash(H256::random())
				.with_shard(H256::random())
				.build_signed(Keyring::Alice.pair()),
			parentchain_effects: Default::default(),
		})
	}
}

impl<SB: SidechainBlockT> LastBlockExt<SB> for StateMock<SB> {
	fn get_last_block(&self) -> Option<SB> {
		self.last_block.clone()
	}

	fn set_last_block(&mut self, block: &SB) {
		self.last_block = Some(block.clone())
	}
}

pub fn validateer(account: AccountId) -> Enclave {
	Enclave::new(account, Default::default(), Default::default(), Default::default())
}

pub struct TestBlockBuilder {
	author: ed25519::Public,
	block_number: u64,
	parent_hash: H256,
	parentchain_head: H256,
	shard: H256,
	signed_top_hashes: Vec<H256>,
	encrypted_payload: Vec<u8>,
	timestamp: u64,
}

impl Default for TestBlockBuilder {
	fn default() -> Self {
		Self {
			author: Default::default(),
			block_number: 1,
			parent_hash: Default::default(),
			parentchain_head: Default::default(),
			shard: Default::default(),
			signed_top_hashes: Default::default(),
			encrypted_payload: Default::default(),
			timestamp: 0,
		}
	}
}

impl TestBlockBuilder {
	pub fn new() -> Self {
		Default::default()
	}

	pub fn with_author(mut self, author: ed25519::Public) -> Self {
		self.author = author;
		self
	}

	pub fn with_parent_hash(mut self, hash: H256) -> Self {
		self.parent_hash = hash;
		self
	}

	pub fn with_parentchain_head(mut self, header: H256) -> Self {
		self.parentchain_head = header;
		self
	}

	pub fn with_block_number(mut self, block_number: u64) -> Self {
		self.block_number = block_number;
		self
	}

	pub fn with_timestamp(mut self, timestamp: u64) -> Self {
		self.timestamp = timestamp;
		self
	}

	pub fn with_shard(mut self, shard: H256) -> Self {
		self.shard = shard;
		self
	}

	pub fn with_encrypted_payload(mut self, payload: Vec<u8>) -> Self {
		self.encrypted_payload = payload;
		self
	}

	pub fn build(self) -> SidechainBlock {
		SidechainBlock::new(
			self.author,
			self.block_number,
			self.parent_hash,
			self.parentchain_head,
			self.shard,
			self.signed_top_hashes,
			self.encrypted_payload,
			self.timestamp,
		)
	}

	/// Build a signed block. Sets the author to Alice and signs it by Alice.
	pub fn build_signed(mut self, authority: AuthorityPair) -> SignedSidechainBlock {
		self.author = authority.public();
		self.build().sign_block(&authority)
	}
}

#[test]
fn build_signed_block_has_valid_signature() {
	let signed_block = TestBlockBuilder::new()
		.with_parentchain_head(H256::random())
		.build_signed(Keyring::Bob.pair());
	assert!(signed_block.verify_signature());
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
