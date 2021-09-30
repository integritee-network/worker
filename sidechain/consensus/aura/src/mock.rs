use crate::{verifier::AuraVerifier, Aura};
use itp_test::mock::onchain_mock::OnchainMock;
use itp_types::{AccountId, Block as ParentchainBlock, Enclave, Header};
use its_consensus_common::{Environment, Error as ConsensusError, Proposal, Proposer};
use its_consensus_slots::duration_now;
use its_primitives::{
	traits::{Block as SidechainBlockT, SignBlock as SignBlockT, SignedBlock as SignedBlockT},
	types::block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
};
use its_state::SidechainSystemExt;
use sp_keyring::ed25519::Keyring;
use sp_runtime::{app_crypto::ed25519, testing::H256, traits::Header as HeaderT};
use std::time::Duration;

pub const SLOT_DURATION: Duration = Duration::from_millis(300);

type AuthorityPair = ed25519::Pair;
pub struct EnvironmentMock;
pub struct ProposerMock;

pub type ShardIdentifierFor<SB> = <<SB as SignedBlockT>::Block as SidechainBlockT>::ShardIdentifier;

pub struct StateMock<SB: SidechainBlockT> {
	pub last_block: Option<SB>,
}

pub type TestAura =
	Aura<AuthorityPair, ParentchainBlock, SignedSidechainBlock, EnvironmentMock, OnchainMock>;

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
		_: Header,
		_: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(ProposerMock)
	}
}

impl Proposer<ParentchainBlock, SignedSidechainBlock> for ProposerMock {
	fn propose(
		&self,
		_max_duration: Duration,
	) -> Result<Proposal<SignedSidechainBlock>, ConsensusError> {
		Ok(Proposal {
			block: test_block_with_time_stamp(duration_now().as_millis() as u64),
			parentchain_effects: Default::default(),
		})
	}
}

impl<SB: SidechainBlockT> SidechainSystemExt<SB> for StateMock<SB> {
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
	layer_one_head: H256,
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
			layer_one_head: Default::default(),
			shard: Default::default(),
			signed_top_hashes: vec![],
			encrypted_payload: vec![],
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

	pub fn with_layer1_head(mut self, header: H256) -> Self {
		self.layer_one_head = header;
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

	pub fn build(self) -> SidechainBlock {
		SidechainBlock::new(
			self.author,
			self.block_number,
			self.parent_hash,
			self.layer_one_head,
			self.shard,
			self.signed_top_hashes,
			self.encrypted_payload,
			self.timestamp,
		)
	}
}

pub fn test_block_with_time_stamp(timestamp: u64) -> SignedSidechainBlock {
	SidechainBlock::new(
		Default::default(),
		1,
		H256::random(),
		H256::random(),
		H256::random(),
		Default::default(),
		Default::default(),
		timestamp,
	)
	.sign_block(&Keyring::Alice.pair())
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
