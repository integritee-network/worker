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

use crate::{
	error::{Error, Result},
	executor::*,
	traits::{StateUpdateProposer, StfExecuteGenericUpdate, StfExecuteTimedGettersBatch},
};
use codec::{Decode, Encode};
use ita_stf::{
	test_genesis::{endowed_account, test_genesis_setup, ENDOWED_ACC_FUNDS},
	AccountId, Balance, ShardIdentifier, State, TrustedCall, TrustedGetter, TrustedGetterSigned,
};
use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock};
use itp_types::H256;
use sgx_tstd::panic;
use sp_core::Pair;
use sp_runtime::app_crypto::sp_core::blake2_256;
use std::{sync::Arc, time::Duration, vec, vec::Vec};

// FIXME: Create unit tests for update_states, execute_shield_funds, execute_trusted_call, execute_trusted_call_on_stf #554

pub fn propose_state_update_executes_all_calls_given_enough_time() {
	// given
	let (stf_executor, ocall_api, state_handler) = stf_executor();
	let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let sender = endowed_account();
	let signed_call_1 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		42,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation_1 = signed_call_1.into_trusted_operation(true);
	let call_operation_hash_1: H256 = blake2_256(&trusted_operation_1.encode()).into();
	let signed_call_2 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		100,
	)
	.sign(&sender.clone().into(), 1, &mrenclave, &shard);
	let trusted_operation_2 = signed_call_2.into_trusted_operation(true);
	let call_operation_hash_2: H256 = blake2_256(&trusted_operation_2.encode()).into();

	let old_state_hash = state_hash(&state_handler.load(&shard).unwrap());

	// when
	let batch_execution_result = stf_executor
		.propose_state_update(
			&vec![trusted_operation_1, trusted_operation_2],
			&ParentchainHeaderBuilder::default().build(),
			&shard,
			Duration::from_secs(1000),
			|state| state,
		)
		.unwrap();

	// then
	assert_eq!(old_state_hash, batch_execution_result.state_hash_before_execution);
	assert_eq!(batch_execution_result.executed_operations.len(), 2);
	assert_eq!(
		batch_execution_result.get_executed_operation_hashes(),
		vec![call_operation_hash_1, call_operation_hash_2]
	);
	// Ensure that state has been updated and not actually written.
	assert_ne!(state_handler.load(&shard).unwrap(), batch_execution_result.state_after_execution);
}

pub fn propose_state_update_executes_only_one_trusted_call_given_not_enough_time() {
	// given
	let (stf_executor, ocall_api, state_handler) = stf_executor();
	let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let sender = endowed_account();
	let signed_call_1 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		42,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation_1 = signed_call_1.into_trusted_operation(true);
	let call_operation_hash_1: H256 = blake2_256(&trusted_operation_1.encode()).into();

	let signed_call_2 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		100,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation_2 = signed_call_2.into_trusted_operation(true);

	let old_state_hash = state_hash(&state_handler.load(&shard).unwrap());

	// when
	let batch_execution_result = stf_executor
		.propose_state_update(
			&vec![trusted_operation_1.clone(), trusted_operation_2.clone()],
			&ParentchainHeaderBuilder::default().build(),
			&shard,
			Duration::from_nanos(50_000),
			|state| state,
		)
		.unwrap();

	// then
	assert_eq!(old_state_hash, batch_execution_result.state_hash_before_execution);
	assert_eq!(batch_execution_result.executed_operations.len(), 1);
	assert_eq!(batch_execution_result.get_executed_operation_hashes(), vec![call_operation_hash_1]);
	// Ensure that state has been updated and not actually written.
	assert_ne!(state_handler.load(&shard).unwrap(), batch_execution_result.state_after_execution);
}

pub fn propose_state_update_executes_no_trusted_calls_given_no_time() {
	// given
	let (stf_executor, ocall_api, state_handler) = stf_executor();
	let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let sender = endowed_account();
	let signed_call_1 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		42,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation_1 = signed_call_1.into_trusted_operation(true);

	let signed_call_2 = TrustedCall::balance_transfer(
		sender.public().into(),
		sender.public().into(),
		100,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation_2 = signed_call_2.into_trusted_operation(true);

	let old_state_hash = state_hash(&state_handler.load(&shard).unwrap());

	// when
	let batch_execution_result = stf_executor
		.propose_state_update(
			&vec![trusted_operation_1.clone(), trusted_operation_2.clone()],
			&ParentchainHeaderBuilder::default().build(),
			&shard,
			Duration::ZERO,
			|state| state,
		)
		.unwrap();

	// then
	assert_eq!(old_state_hash, batch_execution_result.state_hash_before_execution);
	assert_eq!(batch_execution_result.executed_operations.len(), 0);
	assert_eq!(batch_execution_result.get_executed_operation_hashes(), vec![]);
}

pub fn propose_state_update_always_executes_preprocessing_step() {
	// given
	let shard = ShardIdentifier::default();
	let (stf_executor, _, state_handler) = stf_executor();
	let _init_hash = state_handler.initialize_shard(shard).unwrap();
	let key = "my_key".encode();
	let value = "my_value".encode();
	let old_state_hash = state_hash(&state_handler.load(&shard).unwrap());

	// when
	let batch_execution_result = stf_executor
		.propose_state_update(
			&vec![],
			&ParentchainHeaderBuilder::default().build(),
			&shard,
			Duration::ZERO,
			|mut state| {
				state.insert(key.clone(), value.clone());
				state
			},
		)
		.unwrap();

	// then
	assert_eq!(old_state_hash, batch_execution_result.state_hash_before_execution);

	// Ensure that state has been updated.
	let old_state = state_handler.load(&shard).unwrap();
	let retrieved_value = batch_execution_result.state_after_execution.get(key.as_slice()).unwrap();
	assert_eq!(*retrieved_value, value);
	// Ensure that state has not been actually written.
	assert_ne!(old_state, batch_execution_result.state_after_execution);
}

pub fn execute_timed_getters_batch_executes_if_enough_time() {
	// given
	let sender = endowed_account();
	let trusted_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
	let (stf_executor, _, state_handler) = stf_executor();
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let execution_duration = Duration::from_secs(10000);

	// when
	assert!(panic::catch_unwind(|| {
		stf_executor.execute_timed_getters_batch(
			&vec![trusted_getter.clone()],
			&shard,
			execution_duration,
			|trusted_getter_signed: &TrustedGetterSigned,
			 _state_result: Result<Option<Vec<u8>>>| {
				// then
				assert_eq!(*trusted_getter_signed, trusted_getter);
				panic!("test should enter here");
			},
		)
	})
	.is_err());
}

pub fn execute_timed_getters_does_not_execute_more_than_once_if_not_enough_time() {
	// given
	let sender = endowed_account();
	let trusted_getter =
		TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());
	let trusted_getter_two =
		TrustedGetter::reserved_balance(sender.public().into()).sign(&sender.into());
	let (stf_executor, _, state_handler) = stf_executor();
	let (_, shard) = init_state_and_shard_with_state_handler(state_handler.as_ref());
	let execution_duration = Duration::ZERO;

	// when
	stf_executor
		.execute_timed_getters_batch(
			&vec![trusted_getter.clone(), trusted_getter_two],
			&shard,
			execution_duration,
			|trusted_getter_signed: &TrustedGetterSigned,
			 _state_result: Result<Option<Vec<u8>>>| {
				// then (second getter should not be executed)
				assert_eq!(*trusted_getter_signed, trusted_getter);
			},
		)
		.unwrap();
}

pub fn execute_timed_getters_batch_returns_early_when_no_getter() {
	// given
	let shard = ShardIdentifier::default();
	let (stf_executor, _, _) = stf_executor();
	let execution_duration = Duration::from_secs(10000);

	// when
	stf_executor
		.execute_timed_getters_batch(
			&vec![],
			&shard,
			execution_duration,
			|_trusted_getter_signed: &TrustedGetterSigned,
			 _state_result: Result<Option<Vec<u8>>>| {
				// then
				panic!("Test should not enter here");
			},
		)
		.unwrap();
}

pub fn execute_update_works() {
	// given
	let shard = ShardIdentifier::default();
	let (stf_executor, _ocall_api, state_handler) = stf_executor();
	let _init_hash = state_handler.initialize_shard(shard).unwrap();
	let key = "my_key".encode();
	let value = "my_value".encode();
	let old_state_hash = state_hash(&state_handler.load(&shard).unwrap());

	// when
	let (result, updated_state_hash) = stf_executor
		.execute_update::<_, _, Error>(&shard, |mut state| {
			state.insert(key.clone(), value.clone());
			Ok((state, 0))
		})
		.unwrap();

	// then
	assert_eq!(result, 0);
	assert_ne!(updated_state_hash, old_state_hash);

	// Ensure that state has been written.
	let updated_state = state_handler.load(&shard).unwrap();
	let retrieved_value = updated_state.get(key.as_slice()).unwrap();
	assert_eq!(*retrieved_value, value);
}

pub fn get_stf_state_works() {
	let sender = endowed_account();
	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
	let mut state = test_state();

	let encoded_balance = get_stf_state(&signed_getter, &mut state).unwrap().unwrap();

	let balance = Balance::decode(&mut encoded_balance.as_slice()).unwrap();

	assert_eq!(balance, ENDOWED_ACC_FUNDS);
}

pub fn upon_false_signature_get_stf_state_errs() {
	let sender = AccountId::from([0; 32]);
	let wrong_signer = endowed_account();
	let signed_getter = TrustedGetter::free_balance(sender).sign(&wrong_signer.into());
	let mut state = test_state();

	assert!(get_stf_state(&signed_getter, &mut state).is_err());
}

// Helper Functions
fn stf_executor() -> (
	StfExecutor<OnchainMock, HandleStateMock, NodeMetadataRepository<NodeMetadataMock>>,
	Arc<OnchainMock>,
	Arc<HandleStateMock>,
) {
	let ocall_api = Arc::new(OnchainMock::default());
	let state_handler = Arc::new(HandleStateMock::default());
	let node_metadata_repo = Arc::new(NodeMetadataRepository::new(NodeMetadataMock::new()));
	let executor = StfExecutor::new(ocall_api.clone(), state_handler.clone(), node_metadata_repo);
	(executor, ocall_api, state_handler)
}

fn test_state() -> State {
	let mut state = State::new();
	test_genesis_setup(&mut state);
	state
}

/// Returns a test setup initialized `State` with the corresponding `ShardIdentifier`.
pub(crate) fn init_state_and_shard_with_state_handler<S: HandleState<StateT = State>>(
	state_handler: &S,
) -> (State, ShardIdentifier) {
	let shard = ShardIdentifier::default();
	let _hash = state_handler.initialize_shard(shard).unwrap();

	let (lock, mut state) = state_handler.load_for_mutation(&shard).unwrap();
	test_genesis_setup(&mut state);

	state_handler.write_after_mutation(state.clone(), lock, &shard).unwrap();

	(state, shard)
}
