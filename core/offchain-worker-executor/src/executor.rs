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
use itp_stf_interface::system_pallet::SystemPalletEventInterface;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use log::*;
use sp_runtime::traits::Block;
use std::{marker::PhantomData, sync::Arc, time::Duration, vec::Vec};

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
	Stf,
> {
	top_pool_author: Arc<TopPoolAuthor>,
	stf_executor: Arc<StfExecutor>,
	state_handler: Arc<StateHandler>,
	validator_accessor: Arc<ValidatorAccessor>,
	extrinsics_factory: Arc<ExtrinsicsFactory>,
	_phantom: PhantomData<(ParentchainBlock, Stf)>,
}

impl<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
		Stf,
	>
	Executor<
		ParentchainBlock,
		TopPoolAuthor,
		StfExecutor,
		StateHandler,
		ValidatorAccessor,
		ExtrinsicsFactory,
		Stf,
	> where
	ParentchainBlock: Block<Hash = H256>,
	StfExecutor: StateUpdateProposer,
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash>,
	StateHandler: QueryShardState + HandleState<StateT = StfExecutor::Externalities>,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock> + Send + Sync + 'static,
	ExtrinsicsFactory: CreateExtrinsics,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	Stf: SystemPalletEventInterface<StfExecutor::Externalities>,
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
			let trusted_calls = self.top_pool_author.get_pending_trusted_calls(shard);
			debug!("Executing {} trusted calls on shard {:?}", trusted_calls.len(), shard);

			let batch_execution_result = self.stf_executor.propose_state_update(
				&trusted_calls,
				&latest_parentchain_header,
				&shard,
				max_duration,
				|mut state| {
					Stf::reset_events(&mut state);
					state
				},
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

	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifier,
		executed_calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let executed_calls_tuple: Vec<_> = executed_calls
			.iter()
			.map(|e| (e.trusted_operation_or_hash.clone(), e.is_success()))
			.collect();
		let failed_to_remove_hashes =
			self.top_pool_author.remove_calls_from_pool(*shard, executed_calls_tuple);

		let failed_executed_calls: Vec<_> = executed_calls
			.into_iter()
			.filter(|e| failed_to_remove_hashes.contains(&e.trusted_operation_or_hash))
			.collect();

		failed_executed_calls
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use codec::{Decode, Encode};
	use ita_stf::{TrustedCall, TrustedOperation};
	use itc_parentchain_light_client::mocks::validator_access_mock::ValidatorAccessMock;
	use itp_extrinsics_factory::mock::ExtrinsicsFactoryMock;
	use itp_sgx_externalities::SgxExternalitiesTrait;
	use itp_stf_executor::mocks::StfExecutorMock;
	use itp_stf_primitives::types::KeyPair;
	use itp_test::mock::handle_state_mock::HandleStateMock;
	use itp_top_pool_author::mocks::AuthorApiMock;
	use itp_types::Block as ParentchainBlock;
	use sp_core::{ed25519, Pair};
	use std::boxed::Box;

	type TestStateHandler = HandleStateMock;
	type TestStfInterface = SystemPalletEventInterfaceMock;
	type State = <TestStateHandler as HandleState>::StateT;
	type TestTopPoolAuthor = AuthorApiMock<H256, H256>;
	type TestStfExecutor = StfExecutorMock<State>;
	type TestValidatorAccess = ValidatorAccessMock;
	type TestExtrinsicsFactory = ExtrinsicsFactoryMock;
	type TestExecutor = Executor<
		ParentchainBlock,
		TestTopPoolAuthor,
		TestStfExecutor,
		TestStateHandler,
		TestValidatorAccess,
		TestExtrinsicsFactory,
		TestStfInterface,
	>;

	const EVENT_COUNT_KEY: &[u8] = b"event_count";

	struct SystemPalletEventInterfaceMock;

	impl SystemPalletEventInterface<State> for SystemPalletEventInterfaceMock {
		type EventRecord = String;
		type EventIndex = u32;
		type BlockNumber = u32;
		type Hash = String;

		fn get_events(_state: &mut State) -> Vec<Box<Self::EventRecord>> {
			unimplemented!();
		}

		fn get_event_count(state: &mut State) -> Self::EventIndex {
			let encoded_value = state.get(EVENT_COUNT_KEY).unwrap();
			Self::EventIndex::decode(&mut encoded_value.as_slice()).unwrap()
		}

		fn get_event_topics(
			_state: &mut State,
			_topic: &Self::Hash,
		) -> Vec<(Self::BlockNumber, Self::EventIndex)> {
			unimplemented!()
		}

		fn reset_events(state: &mut State) {
			state.insert(EVENT_COUNT_KEY.to_vec(), 0u32.encode());
		}
	}

	#[test]
	fn executing_tops_from_pool_works() {
		let stf_executor = Arc::new(TestStfExecutor::new(State::default()));
		let top_pool_author = Arc::new(TestTopPoolAuthor::default());
		top_pool_author.submit_top(create_trusted_operation().encode(), shard());

		assert_eq!(1, top_pool_author.pending_tops(shard()).unwrap().len());

		let executor = create_executor(top_pool_author.clone(), stf_executor);
		executor.execute().unwrap();

		assert!(top_pool_author.pending_tops(shard()).unwrap().is_empty());
	}

	#[test]
	fn reset_events_is_called() {
		let mut state = State::default();
		let event_count = 5;
		state.insert(EVENT_COUNT_KEY.to_vec(), event_count.encode());

		let stf_executor = Arc::new(TestStfExecutor::new(state));
		assert_eq!(TestStfInterface::get_event_count(&mut stf_executor.get_state()), event_count);

		let top_pool_author = Arc::new(TestTopPoolAuthor::default());

		let executor = create_executor(top_pool_author, stf_executor.clone());

		executor.execute().unwrap();

		assert_eq!(TestStfInterface::get_event_count(&mut stf_executor.get_state()), 0);
	}

	fn create_executor(
		top_pool_author: Arc<TestTopPoolAuthor>,
		stf_executor: Arc<TestStfExecutor>,
	) -> TestExecutor {
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
		let call_signed =
			trusted_call.sign(&KeyPair::Ed25519(Box::new(sender)), 0, &mr_enclave(), &shard());
		TrustedOperation::indirect_call(call_signed)
	}

	fn mr_enclave() -> [u8; 32] {
		[4u8; 32]
	}

	fn shard() -> ShardIdentifier {
		ShardIdentifier::default()
	}
}
