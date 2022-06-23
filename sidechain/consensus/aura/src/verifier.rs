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

use crate::{authorities, slot_author, EnclaveOnChainOCallApi};
use core::marker::PhantomData;
use frame_support::ensure;
use itp_utils::stringify::public_to_string;
use its_consensus_common::{Error as ConsensusError, Verifier};
use its_consensus_slots::{slot_from_timestamp_and_duration, Slot};
use its_state::LastBlockExt;
use its_validateer_fetch::ValidateerFetch;
use log::*;
use sidechain_primitives::{
	traits::{
		Block as SidechainBlockTrait, BlockData, Header as HeaderTrait,
		SignedBlock as SignedSidechainBlockTrait,
	},
	types::block::BlockHash,
};
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

impl<AuthorityPair, ParentchainBlock, SignedSidechainBlock, SidechainState, Context>
	Verifier<ParentchainBlock, SignedSidechainBlock>
	for AuraVerifier<AuthorityPair, ParentchainBlock, SignedSidechainBlock, SidechainState, Context>
where
	AuthorityPair: Pair,
	AuthorityPair::Public: Debug,
	// todo: Relax hash trait bound, but this needs a change to some other parts in the code.
	ParentchainBlock: ParentchainBlockTrait<Hash = BlockHash>,
	SignedSidechainBlock: SignedSidechainBlockTrait<Public = AuthorityPair::Public> + 'static,
	SignedSidechainBlock::Block: SidechainBlockTrait,
	SidechainState: LastBlockExt<SignedSidechainBlock::Block> + Send + Sync,
	Context: ValidateerFetch + EnclaveOnChainOCallApi + Send + Sync,
{
	type BlockImportParams = SignedSidechainBlock;

	type Context = Context;

	fn verify(
		&self,
		signed_block: SignedSidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
		ctx: &Self::Context,
	) -> Result<Self::BlockImportParams, ConsensusError> {
		ensure!(
			signed_block.verify_signature(),
			ConsensusError::BadSidechainBlock(signed_block.block().hash(), "bad signature".into())
		);

		let slot = slot_from_timestamp_and_duration(
			Duration::from_millis(signed_block.block().block_data().timestamp()),
			self.slot_duration,
		);

		// We need to check the ancestry first to ensure that an already imported block does not result
		// in an author verification error, but rather a `BlockAlreadyImported` error.
		match self.sidechain_state.get_last_block() {
			Some(last_block) => verify_block_ancestry::<SignedSidechainBlock::Block>(
				signed_block.block(),
				&last_block,
			)?,
			None => ensure_first_block(signed_block.block())?,
		}

		if let Err(e) = verify_author::<
			AuthorityPair,
			ParentchainBlock::Header,
			SignedSidechainBlock,
			_,
		>(&slot, signed_block.block(), parentchain_header, ctx)
		{
			error!(
				"Author verification for block (number: {}) failed, block will be discarded",
				signed_block.block().header().block_number()
			);
			return Err(e)
		}

		Ok(signed_block)
	}
}

/// Verify that the `blocks` author is the expected author when comparing with onchain data.
fn verify_author<AuthorityPair, ParentchainHeader, SignedSidechainBlock, Context>(
	slot: &Slot,
	block: &SignedSidechainBlock::Block,
	parentchain_head: &ParentchainHeader,
	ctx: &Context,
) -> Result<(), ConsensusError>
where
	AuthorityPair: Pair,
	AuthorityPair::Public: Debug,
	SignedSidechainBlock: SignedSidechainBlockTrait<Public = AuthorityPair::Public> + 'static,
	ParentchainHeader: ParentchainHeaderTrait<Hash = BlockHash>,
	Context: ValidateerFetch + EnclaveOnChainOCallApi,
{
	ensure!(
		parentchain_head.hash() == block.block_data().layer_one_head(),
		ConsensusError::BadParentchainBlock(
			parentchain_head.hash(),
			"Invalid parentchain head".into(),
		)
	);

	let authorities = authorities::<_, AuthorityPair, ParentchainHeader>(ctx, parentchain_head)?;

	let expected_author = slot_author::<AuthorityPair>(*slot, &authorities)
		.ok_or_else(|| ConsensusError::CouldNotGetAuthorities("No authorities found".into()))?;

	ensure!(
		expected_author == block.block_data().block_author(),
		ConsensusError::InvalidAuthority(format!(
			"Expected author: {}, author found in block: {}",
			public_to_string(expected_author),
			public_to_string(block.block_data().block_author())
		))
	);

	Ok(())
}

fn verify_block_ancestry<SidechainBlock: SidechainBlockTrait>(
	block: &SidechainBlock,
	last_block: &SidechainBlock,
) -> Result<(), ConsensusError> {
	// These next two checks might seem redundant at first glance. However, they are distinct (see comments).

	// We have already imported this block.
	ensure!(
		block.header().block_number() > last_block.header().block_number(),
		ConsensusError::BlockAlreadyImported(
			block.header().block_number(),
			last_block.header().block_number()
		)
	);

	// We are missing some blocks between our last known block and the one we're trying to import.
	ensure!(
		last_block.header().block_number() + 1 == block.header().block_number(),
		ConsensusError::BlockAncestryMismatch(
			last_block.header().block_number(),
			last_block.hash(),
			format!(
				"Invalid block number, {} does not succeed {}",
				block.header().block_number(),
				last_block.header().block_number()
			)
		)
	);

	ensure!(
		last_block.hash() == block.header().parent_hash(),
		ConsensusError::BlockAncestryMismatch(
			last_block.header().block_number(),
			last_block.hash(),
			"Parent hash does not match".into(),
		)
	);

	Ok(())
}

fn ensure_first_block<SidechainBlock: SidechainBlockTrait>(
	block: &SidechainBlock,
) -> Result<(), ConsensusError> {
	ensure!(
		block.header().block_number() == 1,
		ConsensusError::InvalidFirstBlock(
			block.header().block_number(),
			"No last block found, expecting first block. But block to import has number != 1"
				.into()
		)
	);
	ensure!(
		block.header().parent_hash() == Default::default(),
		ConsensusError::InvalidFirstBlock(
			block.header().block_number(),
			"No last block found, excepting first block. But block to import has parent_hash != 0"
				.into()
		)
	);

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::{
		fixtures::{types::TestAuraVerifier, validateer, SLOT_DURATION},
		mocks::state_mock::StateMock,
	};
	use core::assert_matches::assert_matches;
	use frame_support::assert_ok;
	use itp_test::{
		builders::parentchain_header_builder::ParentchainHeaderBuilder,
		mock::onchain_mock::OnchainMock,
	};
	use its_test::{
		sidechain_block_builder::SidechainBlockBuilder,
		sidechain_block_data_builder::SidechainBlockDataBuilder,
		sidechain_header_builder::SidechainHeaderBuilder,
	};
	use sidechain_primitives::types::{block::SignedBlock, header::SidechainHeader as Header};
	use sp_keyring::ed25519::Keyring;
	use sp_runtime::testing::H256;

	fn assert_ancestry_mismatch_err<T: Debug>(result: Result<T, ConsensusError>) {
		assert_matches!(result, Err(ConsensusError::BlockAncestryMismatch(_, _, _,)))
	}

	fn block(signer: Keyring, header: Header) -> SignedBlock {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let block_data = SidechainBlockDataBuilder::default()
			.with_signer(signer.pair())
			.with_timestamp(0)
			.with_layer_one_head(parentchain_header.hash())
			.build();

		SidechainBlockBuilder::default()
			.with_header(header)
			.with_block_data(block_data)
			.with_signer(signer.pair())
			.build_signed()
	}

	fn block1(signer: Keyring) -> SignedBlock {
		let header = SidechainHeaderBuilder::default().with_block_number(1).build();

		block(signer, header)
	}

	fn block2(signer: Keyring, parent_hash: H256) -> SignedBlock {
		let header = SidechainHeaderBuilder::default()
			.with_parent_hash(parent_hash)
			.with_block_number(2)
			.build();

		block(signer, header)
	}

	fn block3(signer: Keyring, parent_hash: H256, block_number: u64) -> SignedBlock {
		let header = SidechainHeaderBuilder::default()
			.with_parent_hash(parent_hash)
			.with_block_number(block_number)
			.build();

		block(signer, header)
	}

	#[test]
	fn ensure_first_block_works() {
		let block = SidechainBlockBuilder::default().build();
		assert_ok!(ensure_first_block(&block));
	}

	#[test]
	fn ensure_first_block_errs_with_invalid_block_number() {
		let header = SidechainHeaderBuilder::default().with_block_number(2).build();
		let block = SidechainBlockBuilder::default().with_header(header).build();
		assert_matches!(ensure_first_block(&block), Err(ConsensusError::InvalidFirstBlock(2, _)))
	}

	#[test]
	fn ensure_first_block_errs_with_invalid_parent_hash() {
		let parent = H256::random();
		let header = SidechainHeaderBuilder::default().with_parent_hash(parent).build();
		let block = SidechainBlockBuilder::default().with_header(header).build();

		assert_matches!(ensure_first_block(&block), Err(ConsensusError::InvalidFirstBlock(_, _)));
	}

	#[test]
	fn verify_block_ancestry_works() {
		let last_block = SidechainBlockBuilder::default().build();
		let header = SidechainHeaderBuilder::default()
			.with_parent_hash(last_block.hash())
			.with_block_number(2)
			.build();
		let curr_block = SidechainBlockBuilder::default().with_header(header).build();

		assert_ok!(verify_block_ancestry(&curr_block, &last_block));
	}

	#[test]
	fn verify_block_ancestry_errs_with_invalid_parent_block_number() {
		let last_block = SidechainBlockBuilder::default().build();
		let header = SidechainHeaderBuilder::default()
			.with_parent_hash(last_block.hash())
			.with_block_number(5)
			.build();
		let curr_block = SidechainBlockBuilder::default().with_header(header).build();

		assert_ancestry_mismatch_err(verify_block_ancestry(&curr_block, &last_block));
	}

	#[test]
	fn verify_block_ancestry_errs_with_invalid_parent_hash() {
		let last_block = SidechainBlockBuilder::default().build();
		let header = SidechainHeaderBuilder::default().with_block_number(2).build();
		let curr_block = SidechainBlockBuilder::default().with_header(header).build();

		assert_ancestry_mismatch_err(verify_block_ancestry(&curr_block, &last_block));
	}

	#[test]
	fn verify_works() {
		// block 0
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2(signer, last_block.hash());

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ok!(aura_verifier.verify(curr_block, &parentchain_header, &onchain_mock));
	}

	#[test]
	fn verify_works_for_first_block() {
		let signer = Keyring::Alice;
		let parentchain_header = ParentchainHeaderBuilder::default().build();

		let curr_block = block1(signer);

		let state_mock = StateMock { last_block: None };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ok!(aura_verifier.verify(curr_block, &parentchain_header, &onchain_mock));
	}

	#[test]
	fn verify_errs_on_wrong_authority() {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2(signer, last_block.hash());

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![
				validateer(Keyring::Bob.public().into()),
				validateer(signer.public().into()),
			]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_matches!(
			aura_verifier
				.verify(curr_block, &parentchain_header, &onchain_mock)
				.unwrap_err(),
			ConsensusError::InvalidAuthority(_)
		);
	}

	#[test]
	fn verify_errs_on_invalid_ancestry() {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2(signer, Default::default());

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_ancestry_mismatch_err(aura_verifier.verify(
			curr_block,
			&parentchain_header,
			&onchain_mock,
		));
	}

	#[test]
	fn verify_errs_on_wrong_first_block() {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signer = Keyring::Alice;

		let curr_block = block2(signer, Default::default());

		let state_mock = StateMock { last_block: None };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_matches!(
			aura_verifier.verify(curr_block, &parentchain_header, &onchain_mock),
			Err(ConsensusError::InvalidFirstBlock(2, _))
		);
	}

	#[test]
	fn verify_errs_on_already_imported_block() {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let last_block = SidechainBlockBuilder::default().build();
		let signer = Keyring::Alice;

		// Current block has also number 1, same as last. So import should return an error
		// that a block with this number is already imported.
		let curr_block = block3(signer, last_block.hash(), 1);

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_matches!(
			aura_verifier.verify(curr_block, &parentchain_header, &onchain_mock),
			Err(ConsensusError::BlockAlreadyImported(1, 1))
		);
	}

	#[test]
	fn verify_block_already_imported_error_even_if_parentchain_block_mismatches() {
		// This test is to ensure that we get a 'AlreadyImported' error, when the sidechain block
		// is already imported, and the parentchain block that is passed into the verifier is newer.
		// Important because client of the verifier acts differently for an 'AlreadyImported' error than an 'AncestryErrorMismatch'.
		let signer = Keyring::Alice;

		let parentchain_header_1 = ParentchainHeaderBuilder::default().with_number(1).build();
		let parentchain_header_2 = ParentchainHeaderBuilder::default().with_number(2).build();

		let block_data = SidechainBlockDataBuilder::default()
			.with_layer_one_head(parentchain_header_1.hash())
			.with_signer(signer.pair())
			.build();
		let last_block = SidechainBlockBuilder::default()
			.with_block_data(block_data)
			.with_signer(signer.pair())
			.build();

		let block_data_for_signed_block = SidechainBlockDataBuilder::default()
			.with_layer_one_head(parentchain_header_1.hash())
			.with_signer(signer.pair())
			.build();
		let signed_block_to_verify = SidechainBlockBuilder::default()
			.with_block_data(block_data_for_signed_block)
			.with_signer(signer.pair())
			.build_signed();

		let state_mock = StateMock { last_block: Some(last_block) };
		let onchain_mock = OnchainMock::default().add_validateer_set(
			&parentchain_header_2,
			Some(vec![validateer(signer.public().into())]),
		);

		let aura_verifier = TestAuraVerifier::new(SLOT_DURATION, state_mock);

		assert_matches!(
			aura_verifier.verify(signed_block_to_verify, &parentchain_header_2, &onchain_mock),
			Err(ConsensusError::BlockAlreadyImported(1, 1))
		);
	}
}
