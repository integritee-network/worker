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
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_executor::traits::StateUpdateProposer;
use itp_time_utils::now_as_u64;
use itp_types::H256;
use its_block_composer::ComposeBlockAndConfirmation;
use its_consensus_common::{Error as ConsensusError, Proposal, Proposer};
use its_state::{SidechainDB, SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_executor::call_operator::TopPoolCallOperator;
use log::*;
use sidechain_primitives::traits::{
	Block as SidechainBlockTrait, Header as HeaderTrait, ShardIdentifierFor,
	SignedBlock as SignedSidechainBlockTrait,
};
use sp_runtime::{
	traits::{Block, NumberFor},
	MultiSignature,
};
use std::{marker::PhantomData, string::ToString, sync::Arc, time::Duration, vec::Vec};

pub type ExternalitiesFor<T> = <T as StateUpdateProposer>::Externalities;
///! `SlotProposer` instance that has access to everything needed to propose a sidechain block.
pub struct SlotProposer<
	ParentchainBlock: Block,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	TopPoolExecutor,
	StfExecutor,
	BlockComposer,
> {
	pub(crate) top_pool_executor: Arc<TopPoolExecutor>,
	pub(crate) stf_executor: Arc<StfExecutor>,
	pub(crate) block_composer: Arc<BlockComposer>,
	pub(crate) parentchain_header: ParentchainBlock::Header,
	pub(crate) shard: ShardIdentifierFor<SignedSidechainBlock>,
	pub(crate) _phantom: PhantomData<ParentchainBlock>,
}

impl<ParentchainBlock, SignedSidechainBlock, TopPoolExecutor, BlockComposer, StfExecutor>
	Proposer<ParentchainBlock, SignedSidechainBlock>
	for SlotProposer<
		ParentchainBlock,
		SignedSidechainBlock,
		TopPoolExecutor,
		StfExecutor,
		BlockComposer,
	> where
	ParentchainBlock: Block<Hash = H256>,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	SignedSidechainBlock: SignedSidechainBlockTrait<Public = sp_core::ed25519::Public, Signature = MultiSignature>
		+ 'static,
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = sp_core::ed25519::Public>,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	StfExecutor: StateUpdateProposer,
	ExternalitiesFor<StfExecutor>:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
	TopPoolExecutor:
		TopPoolCallOperator<ParentchainBlock, SignedSidechainBlock> + Send + Sync + 'static,
	BlockComposer: ComposeBlockAndConfirmation<
			ExternalitiesFor<StfExecutor>,
			ParentchainBlock,
			SignedSidechainBlock = SignedSidechainBlock,
		> + Send
		+ Sync
		+ 'static,
{
	/// Proposes a new sidechain block.
	///
	/// This includes the following steps:
	/// 1) Retrieve all trusted calls from the top pool.
	/// 2) Calculate a new state that will be proposed in the sidechain block.
	/// 3) Compose the sidechain block and the parentchain confirmation.
	fn propose(
		&self,
		max_duration: Duration,
	) -> Result<Proposal<SignedSidechainBlock>, ConsensusError> {
		let latest_parentchain_header = &self.parentchain_header;

		// 1) Retrieve trusted calls from top pool.
		let trusted_calls = self
			.top_pool_executor
			.get_trusted_calls(&self.shard)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		if !trusted_calls.is_empty() {
			debug!("Got following trusted calls from pool: {:?}", trusted_calls);
		}

		// 2) Execute trusted calls.
		let batch_execution_result = self
			.stf_executor
			.propose_state_update(
				&trusted_calls,
				latest_parentchain_header,
				&self.shard,
				max_duration,
				|s| {
					let mut sidechain_db = SidechainDB::<
						SignedSidechainBlock::Block,
						ExternalitiesFor<StfExecutor>,
					>::new(s);
					sidechain_db
						.set_block_number(&sidechain_db.get_block_number().map_or(1, |n| n + 1));
					sidechain_db.set_timestamp(&now_as_u64());
					sidechain_db.ext
				},
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		let mut parentchain_extrinsics = batch_execution_result.get_extrinsic_callbacks();

		let executed_operation_hashes: Vec<_> =
			batch_execution_result.get_executed_operation_hashes().to_vec();
		let number_executed_transactions = executed_operation_hashes.len();

		// Remove all not successfully executed operations from the top pool.
		let failed_operations = batch_execution_result.get_failed_operations();
		self.top_pool_executor.remove_calls_from_pool(&self.shard, failed_operations);

		// 3) Compose sidechain block and parentchain confirmation.
		let (confirmation_extrinsic, sidechain_block) = self
			.block_composer
			.compose_block_and_confirmation(
				latest_parentchain_header,
				executed_operation_hashes,
				self.shard,
				batch_execution_result.state_hash_before_execution,
				batch_execution_result.state_after_execution,
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		parentchain_extrinsics.push(confirmation_extrinsic);

		info!(
			"Queue/Timeslot/Transactions: {:?};{};{}",
			trusted_calls.len(),
			max_duration.as_millis(),
			number_executed_transactions
		);

		Ok(Proposal { block: sidechain_block, parentchain_effects: parentchain_extrinsics })
	}
}
