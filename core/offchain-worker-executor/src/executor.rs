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
use itc_parentchain_light_client::{
	concurrent_access::ValidatorAccess, BlockNumberOps, ExtrinsicSender, LightClientState,
	NumberFor,
};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_stf_executor::{traits::StateUpdateProposer, ExecutedOperation};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use log::*;
use sp_runtime::traits::Block;
use std::{marker::PhantomData, sync::Arc, time::Duration, vec, vec::Vec};

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
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash>,
	StateHandler: QueryShardState + HandleState<StateT = StfExecutor::Externalities>,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock> + Send + Sync + 'static,
	ExtrinsicsFactory: CreateExtrinsics,
	NumberFor<ParentchainBlock>: BlockNumberOps,
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

	pub fn execute(&self) -> Result<()> {
		let max_duration = Duration::from_secs(5);
		let latest_parentchain_header = self.get_latest_parentchain_header()?;

		let mut parentchain_effects: Vec<OpaqueCall> = Vec::new();

		let shards = self.state_handler.list_shards()?;
		debug!("Executing calls on {} shard(s)", shards.len());

		for shard in shards {
			let trusted_calls = self.top_pool_author.get_pending_tops_separated(shard)?.0;
			debug!("Executing {} trusted calls on shard {:?}", trusted_calls.len(), shard);

			let batch_execution_result = self.stf_executor.propose_state_update(
				&trusted_calls,
				&latest_parentchain_header,
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

			// TODO: notify parentchain about executed operations? -> add to parentchain effects
		}

		if !parentchain_effects.is_empty() {
			self.send_parentchain_effects(parentchain_effects)?;
		}

		Ok(())
	}

	fn get_latest_parentchain_header(&self) -> Result<ParentchainBlock::Header> {
		let header = self.validator_accessor.execute_on_validator(|v| {
			let latest_parentchain_header = v.latest_finalized_header(v.num_relays())?;
			Ok(latest_parentchain_header)
		})?;
		Ok(header)
	}

	fn apply_state_update(
		&self,
		shard: &ShardIdentifier,
		updated_state: <StfExecutor as StateUpdateProposer>::Externalities,
	) -> Result<()> {
		self.state_handler.reset(updated_state, shard)?;
		Ok(())
	}

	fn send_parentchain_effects(&self, parentchain_effects: Vec<OpaqueCall>) -> Result<()> {
		let extrinsics = self
			.extrinsics_factory
			.create_extrinsics(parentchain_effects.as_slice(), None)?;
		self.validator_accessor
			.execute_mut_on_validator(|v| v.send_extrinsics(extrinsics))?;
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

#[cfg(test)]
mod tests {

	use super::*;
	use codec::Encode;
	use ita_stf::{KeyPair, TrustedCall, TrustedOperation};
	use itc_parentchain_light_client::mocks::validator_access_mock::ValidatorAccessMock;
	use itp_extrinsics_factory::mock::ExtrinsicsFactoryMock;
	use itp_stf_executor::mocks::StfExecutorMock;
	use itp_test::mock::handle_state_mock::HandleStateMock;
	use itp_top_pool_author::mocks::AuthorApiMock;
	use itp_types::Block as ParentchainBlock;
	use sp_core::{ed25519, Pair};

	type TestTopPoolAuthor = AuthorApiMock<H256, H256>;
	type TestStateHandler = HandleStateMock;
	type TestStfExecutor = StfExecutorMock<<TestStateHandler as HandleState>::StateT>;
	type TestValidatorAccess = ValidatorAccessMock;
	type TestExtrinsicsFactory = ExtrinsicsFactoryMock;
	type TestExecutor = Executor<
		ParentchainBlock,
		TestTopPoolAuthor,
		TestStfExecutor,
		TestStateHandler,
		TestValidatorAccess,
		TestExtrinsicsFactory,
	>;

	#[test]
	fn executing_tops_from_pool_works() {
		let top_pool_author = Arc::new(TestTopPoolAuthor::default());
		top_pool_author.submit_top(create_trusted_operation().encode(), shard());

		assert_eq!(1, top_pool_author.pending_tops(shard()).unwrap().len());

		let executor = create_executor(top_pool_author.clone());
		executor.execute().unwrap();

		assert!(top_pool_author.pending_tops(shard()).unwrap().is_empty());
	}

	fn create_executor(top_pool_author: Arc<TestTopPoolAuthor>) -> TestExecutor {
		let stf_executor = Arc::new(TestStfExecutor::default());
		let state_handler = Arc::new(TestStateHandler::from_shard(shard()).unwrap());
		let validator_access = Arc::new(TestValidatorAccess::default());
		let extrinsics_factory = Arc::new(TestExtrinsicsFactory::default());

		TestExecutor::new(
			top_pool_author,
			stf_executor,
			state_handler,
			validator_access,
			extrinsics_factory,
		)
	}

	fn create_trusted_operation() -> TrustedOperation {
		let sender = ed25519::Pair::from_seed(b"33345678901234567890123456789012");
		let receiver = ed25519::Pair::from_seed(b"14565678901234567890123456789012");

		let trusted_call = TrustedCall::balance_transfer(
			sender.public().into(),
			receiver.public().into(),
			10000u128,
		);
		let call_signed = trusted_call.sign(&KeyPair::Ed25519(sender), 0, &mr_enclave(), &shard());
		TrustedOperation::indirect_call(call_signed)
	}

	fn mr_enclave() -> [u8; 32] {
		[4u8; 32]
	}

	fn shard() -> ShardIdentifier {
		ShardIdentifier::default()
	}
}
