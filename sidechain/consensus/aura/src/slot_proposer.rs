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

use codec::Encode;
use finality_grandpa::BlockNumberOps;
use itp_sgx_externalities::{SgxExternalitiesTrait, StateHash};
use itp_stf_executor::traits::StateUpdateProposer;
use itp_time_utils::now_as_millis;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::H256;
use its_block_composer::ComposeBlock;
use its_consensus_common::{Error as ConsensusError, Proposal, Proposer};
use its_primitives::traits::{
	Block as SidechainBlockTrait, Header as HeaderTrait, ShardIdentifierFor,
	SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{SidechainState, SidechainSystemExt};
use log::*;
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
	TopPoolAuthor,
	StfExecutor,
	BlockComposer,
> {
	pub(crate) top_pool_author: Arc<TopPoolAuthor>,
	pub(crate) stf_executor: Arc<StfExecutor>,
	pub(crate) block_composer: Arc<BlockComposer>,
	pub(crate) parentchain_header: ParentchainBlock::Header,
	pub(crate) shard: ShardIdentifierFor<SignedSidechainBlock>,
	pub(crate) _phantom: PhantomData<ParentchainBlock>,
}

impl<ParentchainBlock, SignedSidechainBlock, TopPoolAuthor, BlockComposer, StfExecutor>
	Proposer<ParentchainBlock, SignedSidechainBlock>
	for SlotProposer<ParentchainBlock, SignedSidechainBlock, TopPoolAuthor, StfExecutor, BlockComposer>
where
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
	<ExternalitiesFor<StfExecutor> as SgxExternalitiesTrait>::SgxExternalitiesType: Encode,
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash> + Send + Sync + 'static,
	BlockComposer: ComposeBlock<
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
		let trusted_calls = self.top_pool_author.get_pending_trusted_calls(self.shard);

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
				|mut sidechain_db| {
					sidechain_db.reset_events();
					sidechain_db
						.set_block_number(&sidechain_db.get_block_number().map_or(1, |n| n + 1));
					sidechain_db.set_timestamp(&now_as_millis());
					sidechain_db
				},
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		let parentchain_extrinsics = batch_execution_result.get_extrinsic_callbacks();

		let executed_operation_hashes: Vec<_> =
			batch_execution_result.get_executed_operation_hashes().to_vec();
		let number_executed_transactions = executed_operation_hashes.len();

		// Remove all not successfully executed operations from the top pool.
		let failed_operations = batch_execution_result.get_failed_operations();
		self.top_pool_author.remove_calls_from_pool(
			self.shard,
			failed_operations
				.into_iter()
				.map(|e| {
					let is_success = e.is_success();
					(e.trusted_operation_or_hash, is_success)
				})
				.collect(),
		);

		// 3) Compose sidechain block.
		let sidechain_block = self
			.block_composer
			.compose_block(
				latest_parentchain_header,
				executed_operation_hashes,
				self.shard,
				batch_execution_result.state_hash_before_execution,
				&batch_execution_result.state_after_execution,
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		info!(
			"Queue/Timeslot/Transactions: {:?};{};{}",
			trusted_calls.len(),
			max_duration.as_millis(),
			number_executed_transactions
		);

		Ok(Proposal { block: sidechain_block, parentchain_effects: parentchain_extrinsics })
	}
}
