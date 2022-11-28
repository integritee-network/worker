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
use its_block_verification::verify_sidechain_block;
use its_consensus_common::{Error as ConsensusError, Verifier};
use its_primitives::{
	traits::{Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait},
	types::block::BlockHash,
};
use its_validateer_fetch::ValidateerFetch;
use sp_runtime::{app_crypto::Pair, traits::Block as ParentchainBlockTrait};
use std::{fmt::Debug, time::Duration};

#[derive(Default)]
pub struct AuraVerifier<AuthorityPair, ParentchainBlock, SignedSidechainBlock, Context>
where
	SignedSidechainBlock: SignedSidechainBlockTrait + 'static,
	SignedSidechainBlock::Block: SidechainBlockTrait,
{
	slot_duration: Duration,
	last_sidechain_block: Option<SignedSidechainBlock::Block>,
	_phantom: PhantomData<(AuthorityPair, ParentchainBlock, Context)>,
}

impl<AuthorityPair, ParentchainBlock, SignedSidechainBlock, Context>
	AuraVerifier<AuthorityPair, ParentchainBlock, SignedSidechainBlock, Context>
where
	SignedSidechainBlock: SignedSidechainBlockTrait + 'static,
	SignedSidechainBlock::Block: SidechainBlockTrait,
{
	pub fn new(
		slot_duration: Duration,
		last_sidechain_block: Option<SignedSidechainBlock::Block>,
	) -> Self {
		Self { slot_duration, last_sidechain_block, _phantom: Default::default() }
	}
}

impl<AuthorityPair, ParentchainBlock, SignedSidechainBlock, Context>
	Verifier<ParentchainBlock, SignedSidechainBlock>
	for AuraVerifier<AuthorityPair, ParentchainBlock, SignedSidechainBlock, Context>
where
	AuthorityPair: Pair,
	AuthorityPair::Public: Debug,
	// todo: Relax hash trait bound, but this needs a change to some other parts in the code.
	ParentchainBlock: ParentchainBlockTrait<Hash = BlockHash>,
	SignedSidechainBlock: SignedSidechainBlockTrait<Public = AuthorityPair::Public> + 'static,
	SignedSidechainBlock::Block: SidechainBlockTrait,
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
			&self.last_sidechain_block,
			parentchain_header,
			&authorities,
		)?)
	}
}
