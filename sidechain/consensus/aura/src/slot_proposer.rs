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

use finality_grandpa::BlockNumberOps;
use itp_types::H256;
use its_block_composer::ComposeBlockAndConfirmation;
use its_consensus_common::{Error as ConsensusError, Proposal, Proposer};
use its_primitives::traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock};
use its_top_pool_executor::top_pool_operation_executor::ExecuteCallsOnTopPool;
use sp_core::ed;
use sp_runtime::{
	traits::{Block, NumberFor},
	MultiSignature,
};
use std::{marker::PhantomData, string::ToString, sync::Arc, time::Duration, vec::Vec};

///! `SlotProposer` instance that has access to everything needed to propose a sidechain block
pub struct SlotProposer<PB: Block, SB: SignedBlock, TopPoolExecutor, BlockComposer> {
	pub(crate) top_pool_executor: Arc<TopPoolExecutor>,
	pub(crate) block_composer: Arc<BlockComposer>,
	pub(crate) parentchain_header: PB::Header,
	pub(crate) shard: ShardIdentifierFor<SB>,
	pub(crate) _phantom: PhantomData<PB>,
}

impl<PB, SB, TopPoolExecutor, BlockComposer> Proposer<PB, SB>
	for SlotProposer<PB, SB, TopPoolExecutor, BlockComposer>
where
	PB: Block<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	TopPoolExecutor: ExecuteCallsOnTopPool<ParentchainBlockT = PB> + Send + Sync + 'static,
	BlockComposer: ComposeBlockAndConfirmation<ParentchainBlockT = PB, SidechainBlockT = SB>
		+ Send
		+ Sync
		+ 'static,
{
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SB>, ConsensusError> {
		let latest_onchain_header = &self.parentchain_header;

		let batch_execution_result = self
			.top_pool_executor
			.execute_trusted_calls(latest_onchain_header, self.shard, max_duration)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		let mut parentchain_extrinsics = batch_execution_result.get_extrinsic_callbacks();

		let executed_operation_hashes =
			batch_execution_result.get_executed_operation_hashes().iter().copied().collect();

		let (confirmation_extrinsic, sidechain_block) = self
			.block_composer
			.compose_block_and_confirmation(
				latest_onchain_header,
				executed_operation_hashes,
				self.shard,
				batch_execution_result.previous_state_hash,
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		parentchain_extrinsics.push(confirmation_extrinsic);

		Ok(Proposal { block: sidechain_block, parentchain_effects: parentchain_extrinsics })
	}
}
