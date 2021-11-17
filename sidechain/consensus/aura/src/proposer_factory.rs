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

use crate::slot_proposer::SlotProposer;
use finality_grandpa::BlockNumberOps;
use itp_types::H256;
use its_block_composer::ComposeBlockAndConfirmation;
use its_consensus_common::{Environment, Error as ConsensusError};
use its_primitives::traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock};
use its_top_pool_executor::top_pool_operation_executor::ExecuteCallsOnTopPool;
use sp_runtime::{
	traits::{Block, NumberFor},
	MultiSignature,
};
use std::{marker::PhantomData, sync::Arc};

///! `ProposerFactory` instance containing all the data to create the `SlotProposer` for the
/// next `Slot`.
pub struct ProposerFactory<PB: Block, TopPoolExecutor, BlockComposer> {
	top_pool_executor: Arc<TopPoolExecutor>,
	block_composer: Arc<BlockComposer>,
	_phantom: PhantomData<PB>,
}

impl<PB: Block, TopPoolExecutor, BlockComposer>
	ProposerFactory<PB, TopPoolExecutor, BlockComposer>
{
	pub fn new(
		top_pool_executor: Arc<TopPoolExecutor>,
		block_composer: Arc<BlockComposer>,
	) -> Self {
		Self { top_pool_executor, block_composer, _phantom: Default::default() }
	}
}

impl<PB: Block<Hash = H256>, SB, TopPoolExecutor, BlockComposer> Environment<PB, SB>
	for ProposerFactory<PB, TopPoolExecutor, BlockComposer>
where
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	TopPoolExecutor: ExecuteCallsOnTopPool<ParentchainBlockT = PB> + Send + Sync + 'static,
	BlockComposer: ComposeBlockAndConfirmation<ParentchainBlockT = PB, SidechainBlockT = SB>
		+ Send
		+ Sync
		+ 'static,
{
	type Proposer = SlotProposer<PB, SB, TopPoolExecutor, BlockComposer>;
	type Error = ConsensusError;

	fn init(
		&mut self,
		parent_header: PB::Header,
		shard: ShardIdentifierFor<SB>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(SlotProposer {
			top_pool_executor: self.top_pool_executor.clone(),
			block_composer: self.block_composer.clone(),
			parentchain_header: parent_header,
			shard,
			_phantom: PhantomData,
		})
	}
}
