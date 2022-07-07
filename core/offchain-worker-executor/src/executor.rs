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

use crate::error::Result;
use ita_stf::hash::TrustedOperationOrHash;
use itc_parentchain_block_import_dispatcher::import_event_listener::ListenToImportEvent;
use itp_stf_executor::{traits::StateUpdateProposer, ExecutedOperation};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_top_pool_author::traits::{AuthorApi, OnBlockImported, SendState};
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use log::*;
use sp_runtime::traits::{Block, Header};
use std::{marker::PhantomData, sync::Arc, time::Duration};

/// Off-chain worker executor implementation.
///
/// Executes calls found in the top-pool and immediately applies the corresponding state diffs.
/// - Sends confirmations for all executed calls (TODO)
/// - Sends extrinsics for any parentchain effects (such as unshield calls).
///
/// The trigger to start executing calls is given when the parentchain block imported event is
/// signaled (event listener).
pub struct Executor<
	ParentchainBlock,
	TopPoolAuthor,
	StfExecutor,
	StateHandler,
	ValidatorAccessor,
	ExtrinsicsFactory,
> {
	top_pool_author: Arc<TopPoolAuthor>,
	stf_executor: Arc<StfExecutor>,
	state_handler: Arc<StateHandler>,
	validator_accessor: Arc<ValidatorAccessor>,
	extrinsics_factory: Arc<ExtrinsicsFactory>,
	_phantom: PhantomData<ParentchainBlock>,
}

impl<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
	>
	Executor<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
	> where
	ParentchainBlock: Block<Hash = H256>,
	StfExecutor: StateUpdateProposer,
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash>
		+ OnBlockImported<Hash = ParentchainBlock::Hash>
		+ SendState<Hash = ParentchainBlock::Hash>,
	StateHandler: QueryShardState + HandleState<StateT = StfExecutor::Externalities>,
{
	pub fn new(
		top_pool_author: Arc<TopPoolAuthor>,
		stf_executor: Arc<StfExecutor>,
		state_handler: Arc<StateHandler>,
		validator_accessor: Arc<ValidatorAccessor>,
		extrinsics_factory: Arc<ExtrinsicsFactory>,
	) -> Self {
		Self {
			top_pool_author,
			stf_executor,
			state_handler,
			validator_accessor,
			extrinsics_factory,
			_phantom: Default::default(),
		}
	}

	pub fn execute(
		&self,
		latest_parentchain_header: &ParentchainBlock::Header,
	) -> Result<Vec<OpaqueCall>> {
		let max_duration = Duration::from_secs(5);

		let mut parentchain_effects: Vec<OpaqueCall> = Vec::new();

		let shards = self.state_handler.list_shards()?;
		for shard in shards {
			let trusted_calls = self.top_pool_author.get_pending_tops_separated(shard)?.0;
			debug!("Executing {} trusted calls on shard {:?}", trusted_calls.len(), shard);

			let batch_execution_result = self.stf_executor.propose_state_update(
				&trusted_calls,
				latest_parentchain_header,
				&shard,
				max_duration,
				|s| s,
			)?;

			parentchain_effects
				.append(&mut batch_execution_result.get_extrinsic_callbacks().clone());

			let failed_operations = batch_execution_result.get_failed_operations();
			let successful_operations: Vec<ExecutedOperation> = batch_execution_result
				.get_executed_operation_hashes()
				.into_iter()
				.map(|h| ExecutedOperation::success(h, TrustedOperationOrHash::Hash(h), Vec::new()))
				.collect();

			// Remove all not successfully executed operations from the top pool.
			self.remove_calls_from_pool(&shard, failed_operations);

			// Apply the state update
			self.apply_state_update(&shard, batch_execution_result.state_after_execution)?;

			// Remove successful operations from pool
			self.remove_calls_from_pool(&shard, successful_operations);

			// TODO: notify parentchain about executed operations?
		}

		Ok(parentchain_effects)
	}

	fn apply_state_update(
		&self,
		shard: &ShardIdentifier,
		updated_state: <StfExecutor as StateUpdateProposer>::Externalities,
	) -> Result<()> {
		self.state_handler.reset(updated_state, shard)?;
		Ok(())
	}

	// TODO: this is duplicated code and should be removed, once we refactor the top pool author
	// and integrate the top pool executor into it.
	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifier,
		executed_calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let mut failed_to_remove = Vec::new();
		for executed_call in executed_calls {
			if let Err(e) = self.top_pool_author.remove_top(
				vec![executed_call.trusted_operation_or_hash.clone()],
				*shard,
				executed_call.is_success(),
			) {
				// We don't want to return here before all calls have been iterated through,
				// hence only throwing an error log and push to `failed_to_remove` vec.
				error!("Error removing trusted call from top pool: Error: {:?}", e);
				failed_to_remove.push(executed_call);
			}
		}
		failed_to_remove
	}
}

impl<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
	> ListenToImportEvent
	for Executor<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
	> where
	ParentchainBlock: Block<Hash = H256>,
	StfExecutor: StateUpdateProposer,
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash>
		+ OnBlockImported<Hash = ParentchainBlock::Hash>
		+ SendState<Hash = ParentchainBlock::Hash>,
	StateHandler: QueryShardState + HandleState<StateT = StfExecutor::Externalities>,
{
	/// We get notified about parentchain block import events.
	/// This triggers executing calls from the TOP pool (synchronously).
	fn notify(&self) {
		// match self.execute(latest_parentchain_header) {
		// 	Ok(parentchain_effects) => {},
		// 	Err(e) => {},
		// }
	}
}
