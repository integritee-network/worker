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

use crate::slot_proposer::{ExternalitiesFor, SlotProposer};
use finality_grandpa::BlockNumberOps;
use itp_stf_executor::traits::StateUpdateProposer;
use itp_types::H256;
use its_block_composer::ComposeBlockAndConfirmation;
use its_consensus_common::{Environment, Error as ConsensusError};
use its_primitives::traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock};
use its_state::{SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_executor::call_operator::TopPoolCallOperator;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{
	traits::{Block, NumberFor},
	MultiSignature,
};
use std::{marker::PhantomData, sync::Arc};

///! `ProposerFactory` instance containing all the data to create the `SlotProposer` for the
/// next `Slot`.
pub struct ProposerFactory<PB: Block, TopPoolExecutor, StfExecutor, BlockComposer> {
	top_pool_executor: Arc<TopPoolExecutor>,
	stf_executor: Arc<StfExecutor>,
	block_composer: Arc<BlockComposer>,
	_phantom: PhantomData<PB>,
}

impl<PB: Block, TopPoolExecutor, StfExecutor, BlockComposer>
	ProposerFactory<PB, TopPoolExecutor, StfExecutor, BlockComposer>
{
	pub fn new(
		top_pool_executor: Arc<TopPoolExecutor>,
		stf_executor: Arc<StfExecutor>,
		block_composer: Arc<BlockComposer>,
	) -> Self {
		Self { top_pool_executor, stf_executor, block_composer, _phantom: Default::default() }
	}
}

impl<PB: Block<Hash = H256>, SB, TopPoolExecutor, StfExecutor, BlockComposer> Environment<PB, SB>
	for ProposerFactory<PB, TopPoolExecutor, StfExecutor, BlockComposer>
where
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	TopPoolExecutor: TopPoolCallOperator<PB, SB> + Send + Sync + 'static,
	StfExecutor: StateUpdateProposer + Send + Sync + 'static,
	ExternalitiesFor<StfExecutor>:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
	BlockComposer: ComposeBlockAndConfirmation<ExternalitiesFor<StfExecutor>, PB, SidechainBlockT = SB>
		+ Send
		+ Sync
		+ 'static,
{
	type Proposer = SlotProposer<PB, SB, TopPoolExecutor, StfExecutor, BlockComposer>;
	type Error = ConsensusError;

	fn init(
		&mut self,
		parent_header: PB::Header,
		shard: ShardIdentifierFor<SB>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(SlotProposer {
			top_pool_executor: self.top_pool_executor.clone(),
			stf_executor: self.stf_executor.clone(),
			block_composer: self.block_composer.clone(),
			parentchain_header: parent_header,
			shard,
			_phantom: PhantomData,
		})
	}
}
