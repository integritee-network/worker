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

use crate::{authorities, slot_author};
use core::marker::PhantomData;
use frame_support::ensure;
use itp_storage_verifier::GetStorageVerified;
use its_consensus_common::{Error as ConsensusError, Verifier};
use its_consensus_slots::{slot_from_time_stamp_and_duration, Slot};
use its_primitives::{
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlock},
	types::block::BlockHash,
};
use its_state::LastBlockExt;
use its_validateer_fetch::ValidateerFetch;
use sp_runtime::{
	app_crypto::Pair,
	traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait},
};
use std::{fmt::Debug, time::Duration};

#[derive(Default)]
pub struct AuraVerifier<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainState, Context> {
	slot_duration: Duration,
	sidechain_state: SidechainState,
	_phantom: PhantomData<(AuthorityPair, ParentchainBlock, SidechainBlock, Context)>,
}

impl<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainState, Context>
	AuraVerifier<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainState, Context>
{
	pub fn new(slot_duration: Duration, sidechain_state: SidechainState) -> Self {
		Self { slot_duration, sidechain_state, _phantom: Default::default() }
	}
}

impl<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainState, Context>
	Verifier<ParentchainBlock, SidechainBlock>
	for AuraVerifier<AuthorityPair, ParentchainBlock, SidechainBlock, SidechainState, Context>
where
	AuthorityPair: Pair,
	AuthorityPair::Public: Debug,
	// todo: Relax hash trait bound, but this needs a change to some other parts in the code.
	ParentchainBlock: ParentchainBlockTrait<Hash = BlockHash>,
	SidechainBlock: SignedSidechainBlock<Public = AuthorityPair::Public> + 'static,
	SidechainBlock::Block: SidechainBlockTrait,
	SidechainState: LastBlockExt<SidechainBlock::Block> + Send + Sync,
	Context: ValidateerFetch + GetStorageVerified + Send + Sync,
{
	type BlockImportParams = SidechainBlock;

	type Context = Context;

	fn verify(
		&mut self,
		signed_block: SidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
		ctx: &Self::Context,
	) -> Result<Self::BlockImportParams, ConsensusError> {
		ensure!(
			signed_block.verify_signature(),
			ConsensusError::BadSidechainBlock(signed_block.block().hash(), "bad signature".into())
		);

		let slot = slot_from_time_stamp_and_duration(
			Duration::from_millis(signed_block.block().timestamp()),
			self.slot_duration,
		);

		verify_author::<AuthorityPair, ParentchainBlock::Header, SidechainBlock, _>(
			&slot,
			signed_block.block(),
			parentchain_header,
			ctx,
		)?;

		match self.sidechain_state.get_last_block() {
			Some(last_block) =>
				verify_block_ancestry::<SidechainBlock::Block>(signed_block.block(), &last_block)?,
			None => ensure_first_block(signed_block.block())?,
		}

		Ok(signed_block)
	}
}

/// Verify that the `blocks` author is the expected author when comparing with onchain data.
fn verify_author<AuthorityPair, ParentchainHeader, SidechainBlock, Context>(
	slot: &Slot,
	block: &SidechainBlock::Block,
	parentchain_head: &ParentchainHeader,
	ctx: &Context,
) -> Result<(), ConsensusError>
where
	AuthorityPair: Pair,
	AuthorityPair::Public: Debug,
	SidechainBlock: SignedSidechainBlock<Public = AuthorityPair::Public> + 'static,
	ParentchainHeader: ParentchainHeaderTrait<Hash = BlockHash>,
	Context: ValidateerFetch + GetStorageVerified,
{
	ensure!(
		parentchain_head.hash() == block.layer_one_head(),
		ConsensusError::BadParentchainBlock(
			parentchain_head.hash(),
			"Invalid parentchain head".into(),
		)
	);

	let authorities = authorities::<_, AuthorityPair, ParentchainHeader>(ctx, parentchain_head)?;

	let expected_author = slot_author::<AuthorityPair>(*slot, &authorities)
		.ok_or_else(|| ConsensusError::CouldNotGetAuthorities("No authorities found".into()))?;

	ensure!(
		expected_author == block.block_author(),
		ConsensusError::InvalidAuthority(format!("{:?}", block.block_author()))
	);

	Ok(())
}

fn verify_block_ancestry<SidechainBlock: SidechainBlockTrait>(
	block: &SidechainBlock,
	last_block: &SidechainBlock,
) -> Result<(), ConsensusError> {
	ensure!(
		last_block.block_number() + 1 == block.block_number(),
		ConsensusError::BadSidechainBlock(block.hash(), "Invalid block number".into())
	);

	ensure!(
		last_block.hash() == block.parent_hash(),
		ConsensusError::BadSidechainBlock(block.hash(), "Parent hash does not match".into(),)
	);

	Ok(())
}

fn ensure_first_block<SidechainBlock: SidechainBlockTrait>(
	block: &SidechainBlock,
) -> Result<(), ConsensusError> {
	ensure!(
		block.block_number() == 1,
		ConsensusError::BadSidechainBlock(
			block.hash(),
			"No last block found but block number != 1".into()
		)
	);
	ensure!(
		block.parent_hash() == Default::default(),
		ConsensusError::BadSidechainBlock(
			block.hash(),
			"No last block found parent_hash != 0".into()
		)
	);

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{default_header, validateer, StateMock, TestAuraVerifier, SLOT_DURATION};
	use core::assert_matches::assert_matches;
	use frame_support::assert_ok;
	use itp_test::mock::onchain_mock::OnchainMock;
	use its_test::sidechain_block_builder::SidechainBlockBuilder;
	use sp_keyring::ed25519::Keyring;
	use sp_runtime::{app_crypto::ed25519, testing::H256};

	fn assert_bad_sidechain_block_err<T: Debug>(result: Result<T, ConsensusError>, msg: &str) {
		assert_matches!(result, Err(ConsensusError::BadSidechainBlock(
			_,
			m,
		)) if m == msg)
	}

	fn assert_ancestry_mismatch_err<T: Debug>(result: Result<T, ConsensusError>, msg: &str) {
		assert_matches!(result, Err(ConsensusError::BlockAncestryMismatch(
			_,
			m,
		)) if m == msg)
	}

	fn assert_ancestry_mismatch_err<T: Debug>(result: Result<T, ConsensusError>, msg: &str) {
		assert_matches!(result.unwrap_err(),ConsensusError::BlockAncestryMismatch(
			_,
			m,
		) if &m == msg)
	}

	fn block2_builder(signer: ed25519::Pair, parent_hash: H256) -> SidechainBlockBuilder {
		block1_builder(signer).with_parent_hash(parent_hash).with_number(2)
	}

	fn block1_builder(signer: ed25519::Pair) -> SidechainBlockBuilder {
		SidechainBlockBuilder::default()
			.with_signer(signer)
			.with_parentchain_block_hash(default_header().hash())
			.with_number(1)
			.with_timestamp(0)
	}

	#[test]
	fn ensure_first_block_works() {
		let b = SidechainBlockBuilder::default().build();
		assert_ok!(ensure_first_block(&b));
	}

	#[test]
	fn ensure_first_block_errs_with_invalid_block_number() {
		let b = SidechainBlockBuilder::default().with_number(2).build();
		assert_bad_sidechain_block_err(
			ensure_first_block(&b),
			"No last block found but block number != 1",
		)
	}

	#[test]
	fn ensure_first_block_errs_with_invalid_parent_hash() {
		let parent = H256::random();
		let b = SidechainBlockBuilder::default().with_parent_hash(parent).build();

		assert_bad_sidechain_block_err(
			ensure_first_block(&b),
			"No last block found parent_hash != 0",
		);
	}

	#[test]
	fn verify_block_ancestry_works() {
		let last_block = SidechainBlockBuilder::default().build();
		let curr_block = SidechainBlockBuilder::default()
			.with_parent_hash(last_block.hash())
			.with_number(2)
			.build();

		assert_ok!(verify_block_ancestry(&curr_block, &last_block));
	}

	#[test]
	fn verify_block_ancestry_errs_with_invalid_parent_block_number() {
		let last_block = SidechainBlockBuilder::default().build();
		let curr_block =
			SidechainBlockBuilder::default().with_parent_hash(last_block.hash()).build();

		assert_ancestry_mismatch_err(
			verify_block_ancestry(&curr_block, &last_block),
			"Invalid block number",
		);
	}

	#[test]
	fn verify_block_ancestry_errs_with_invalid_parent_hash() {
		let last_block = SidechainBlockBuilder::default().build();
		let curr_block = SidechainBlockBuilder::default().with_number(2).build();

		assert_ancestry_mismatch_err(
			verify_block_ancestry(&curr_block, &last_block),
			"Parent hash does not match",
		);
	}

	#[test]
	fn verify_works() {
		// block 0
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2_builder(signer.pair(), last_block.hash()).build_signed();

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default()
			.with_validateer_set(Some(vec![validateer(signer.public().into())]));

		let mut aura = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ok!(aura.verify(curr_block, &default_header(), &onchain_mock));
	}

	#[test]
	fn verify_works_for_first_block() {
		let signer = Keyring::Alice;

		let curr_block = block1_builder(signer.pair()).build_signed();

		let state_mock = StateMock { last_block: None };
		let onchain_mock = OnchainMock::default()
			.with_validateer_set(Some(vec![validateer(signer.public().into())]));

		let mut aura = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ok!(aura.verify(curr_block, &default_header(), &onchain_mock));
	}

	#[test]
	fn verify_errs_on_wrong_authority() {
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2_builder(signer.pair(), last_block.hash()).build_signed();

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().with_validateer_set(Some(vec![
			validateer(Keyring::Bob.public().into()),
			validateer(signer.public().into()),
		]));

		let mut aura = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_matches!(
			aura.verify(curr_block, &default_header(), &onchain_mock).unwrap_err(),
			ConsensusError::InvalidAuthority(_)
		);
	}

	#[test]
	fn verify_errs_on_invalid_ancestry() {
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2_builder(signer.pair(), Default::default()).build_signed();

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default()
			.with_validateer_set(Some(vec![validateer(signer.public().into())]));

		let mut aura = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ancestry_mismatch_err(
			aura.verify(curr_block, &default_header(), &onchain_mock),
			"Parent hash does not match",
		);
	}

	#[test]
	fn verify_errs_on_wrong_first_block() {
		let signer = Keyring::Alice;

		let curr_block = block2_builder(signer.pair(), Default::default()).build_signed();

		let state_mock = StateMock { last_block: None };
		let onchain_mock = OnchainMock::default()
			.with_validateer_set(Some(vec![validateer(signer.public().into())]));

		let mut aura = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_bad_sidechain_block_err(
			aura.verify(curr_block, &default_header(), &onchain_mock),
			"No last block found but block number != 1",
		);
	}
}
