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

use crate::{authorities, EnclaveOnChainOCallApi};
use core::marker::PhantomData;
use its_consensus_common::{Error as ConsensusError, Verifier};
use its_state::LastBlockExt;
use its_validateer_fetch::ValidateerFetch;
use sidechain_block_verification::verify_sidechain_block;
use sidechain_primitives::{
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait},
	types::block::BlockHash,
};
use sp_runtime::{app_crypto::Pair, traits::Block as ParentchainBlockTrait};
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
		let authorities =
			authorities::<_, AuthorityPair, ParentchainBlock::Header>(ctx, parentchain_header)?;

		Ok(verify_sidechain_block::<AuthorityPair, ParentchainBlock, SignedSidechainBlock>(
			signed_block,
			self.slot_duration,
			&self.sidechain_state.get_last_block(),
			parentchain_header,
			&authorities,
		)?)
	}
}
