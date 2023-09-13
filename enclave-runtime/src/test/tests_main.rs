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

#[cfg(feature = "evm")]
use crate::test::evm_pallet_tests;

use crate::{
	rpc,
	sync::tests::{enclave_rw_lock_works, sidechain_rw_lock_works},
	test::{
		cert_tests::*,
		direct_rpc_tests, enclave_signer_tests,
		fixtures::test_setup::{
			enclave_call_signer, test_setup, TestStf, TestStfExecutor, TestTopPoolAuthor,
		},
		mocks::types::TestStateKeyRepo,
		sidechain_aura_tests, sidechain_event_tests, state_getter_tests, top_pool_tests,
	},
	tls_ra,
};
use codec::Decode;
use ita_sgx_runtime::Parentchain;
use ita_stf::{
	helpers::{account_key_hash, set_block_number},
	stf_sgx_tests,
	test_genesis::{endowed_account as funded_pair, unendowed_account},
	AccountInfo, Getter, State, StatePayload, TrustedCall, TrustedCallSigned, TrustedGetter,
	TrustedOperation,
};
use itp_node_api::metadata::{metadata_mocks::NodeMetadataMock, provider::NodeMetadataRepository};
use itp_sgx_crypto::{Aes, StateCrypto};
use itp_sgx_externalities::{SgxExternalitiesDiffType, SgxExternalitiesTrait, StateHash};
use itp_stf_executor::{
	executor_tests as stf_executor_tests, traits::StateUpdateProposer, BatchExecutionResult,
};
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInterface,
	system_pallet::{SystemPalletAccountInterface, SystemPalletEventInterface},
	StateCallInterface,
};
use itp_stf_primitives::types::ShardIdentifier;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::handle_state_mock;
use itp_top_pool_author::{test_utils::submit_operation_to_top_pool, traits::AuthorApi};
use itp_types::{AccountId, Block, Header};
use its_primitives::{
	traits::{
		Block as BlockTrait, BlockData, Header as SidechainHeaderTrait,
		SignedBlock as SignedBlockTrait,
	},
	types::block::SignedBlock,
};
use its_sidechain::{
	block_composer::{BlockComposer, ComposeBlock},
	state::SidechainSystemExt,
};
use sgx_tunittest::*;
use sgx_types::size_t;
use sp_core::{crypto::Pair, ed25519 as spEd25519, H256};
use sp_runtime::traits::Header as HeaderT;
use std::{string::String, sync::Arc, time::Duration, vec::Vec};

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	rsgx_unit_tests!(
		itp_attestation_handler::attestation_handler::tests::decode_spid_works,
		stf_sgx_tests::enclave_account_initialization_works,
		stf_sgx_tests::shield_funds_increments_signer_account_nonce,
		stf_sgx_tests::test_root_account_exists_after_initialization,
		itp_stf_state_handler::test::sgx_tests::test_write_and_load_state_works,
		itp_stf_state_handler::test::sgx_tests::test_sgx_state_decode_encode_works,
		itp_stf_state_handler::test::sgx_tests::test_encrypt_decrypt_state_type_works,
		itp_stf_state_handler::test::sgx_tests::test_write_access_locks_read_until_finished,
		itp_stf_state_handler::test::sgx_tests::test_ensure_subsequent_state_loads_have_same_hash,
		itp_stf_state_handler::test::sgx_tests::test_state_handler_file_backend_is_initialized,
		itp_stf_state_handler::test::sgx_tests::test_multiple_state_updates_create_snapshots_up_to_cache_size,
		itp_stf_state_handler::test::sgx_tests::test_state_files_from_handler_can_be_loaded_again,
		itp_stf_state_handler::test::sgx_tests::test_file_io_get_state_hash_works,
		itp_stf_state_handler::test::sgx_tests::test_list_state_ids_ignores_files_not_matching_the_pattern,
		itp_stf_state_handler::test::sgx_tests::test_in_memory_state_initializes_from_shard_directory,
		itp_sgx_crypto::tests::aes_sealing_works,
		itp_sgx_crypto::tests::using_get_aes_repository_twice_initializes_key_only_once,
		itp_sgx_crypto::tests::ed25529_sealing_works,
		itp_sgx_crypto::tests::using_get_ed25519_repository_twice_initializes_key_only_once,
		itp_sgx_crypto::tests::rsa3072_sealing_works,
		itp_sgx_crypto::tests::using_get_rsa3072_repository_twice_initializes_key_only_once,
		test_compose_block,
		test_submit_trusted_call_to_top_pool,
		test_submit_trusted_getter_to_top_pool,
		test_differentiate_getter_and_call_works,
		test_create_block_and_confirmation_works,
		test_create_state_diff,
		test_executing_call_updates_account_nonce,
		test_call_set_update_parentchain_block,
		test_invalid_nonce_call_is_not_executed,
		test_signature_must_match_public_sender_in_call,
		test_non_root_shielding_call_is_not_executed,
		test_shielding_call_with_enclave_self_is_executed,
		test_retrieve_events,
		test_retrieve_event_count,
		test_reset_events,
		rpc::worker_api_direct::tests::test_given_io_handler_methods_then_retrieve_all_names_as_string,
		handle_state_mock::tests::initialized_shards_list_is_empty,
		handle_state_mock::tests::shard_exists_after_inserting,
		handle_state_mock::tests::from_shard_works,
		handle_state_mock::tests::initialize_creates_default_state,
		handle_state_mock::tests::load_mutate_and_write_works,
		handle_state_mock::tests::ensure_subsequent_state_loads_have_same_hash,
		handle_state_mock::tests::ensure_encode_and_encrypt_does_not_affect_state_hash,
		// mra cert tests
		test_verify_mra_cert_should_work,
		test_verify_wrong_cert_is_err,
		test_given_wrong_platform_info_when_verifying_attestation_report_then_return_error,
		// sync tests
		sidechain_rw_lock_works,
		enclave_rw_lock_works,
		// unit tests of stf_executor
		stf_executor_tests::propose_state_update_always_executes_preprocessing_step,
		stf_executor_tests::propose_state_update_executes_no_trusted_calls_given_no_time,
		stf_executor_tests::propose_state_update_executes_only_one_trusted_call_given_not_enough_time,
		stf_executor_tests::propose_state_update_executes_all_calls_given_enough_time,
		enclave_signer_tests::enclave_signer_signatures_are_valid,
		enclave_signer_tests::derive_key_is_deterministic,
		enclave_signer_tests::nonce_is_computed_correctly,
		state_getter_tests::state_getter_works,
		// sidechain integration tests
		sidechain_aura_tests::produce_sidechain_block_and_import_it,
		sidechain_event_tests::ensure_events_get_reset_upon_block_proposal,
		top_pool_tests::process_indirect_call_in_top_pool,
		top_pool_tests::submit_shielding_call_to_top_pool,
		// tls_ra unit tests
		tls_ra::seal_handler::test::seal_shielding_key_works,
		tls_ra::seal_handler::test::seal_shielding_key_fails_for_invalid_key,
		tls_ra::seal_handler::test::unseal_seal_shielding_key_works,
		tls_ra::seal_handler::test::seal_state_key_works,
		tls_ra::seal_handler::test::seal_state_key_fails_for_invalid_key,
		tls_ra::seal_handler::test::unseal_seal_state_key_works,
		tls_ra::seal_handler::test::seal_state_works,
		tls_ra::seal_handler::test::seal_state_fails_for_invalid_state,
		tls_ra::seal_handler::test::unseal_seal_state_works,
		tls_ra::tests::test_tls_ra_server_client_networking,
		tls_ra::tests::test_state_and_key_provisioning,
		// RPC tests
		direct_rpc_tests::get_state_request_works,

		// EVM tests
		run_evm_tests,

		// light-client-test
		itc_parentchain::light_client::io::sgx_tests::init_parachain_light_client_works,
		itc_parentchain::light_client::io::sgx_tests::sealing_creates_backup,

		// these unit test (?) need an ipfs node running..
		// ipfs::test_creates_ipfs_content_struct_works,
		// ipfs::test_verification_ok_for_correct_content,
		// ipfs::test_verification_fails_for_incorrect_content,
		// test_ocall_read_write_ipfs,

		// Teeracle tests
		run_teeracle_tests,
	)
}

#[cfg(feature = "teeracle")]
fn run_teeracle_tests() {
	use super::teeracle_tests::*;
	test_verify_get_exchange_rate_from_coin_gecko_works();
	// Disabled - requires API key, cannot run locally
	//test_verify_get_exchange_rate_from_coin_market_cap_works();
}

#[cfg(not(feature = "teeracle"))]
fn run_teeracle_tests() {}

#[cfg(feature = "evm")]
fn run_evm_tests() {
	evm_pallet_tests::test_evm_call();
	evm_pallet_tests::test_evm_counter();
	evm_pallet_tests::test_evm_create();
	evm_pallet_tests::test_evm_create2();
}
#[cfg(not(feature = "evm"))]
fn run_evm_tests() {}

fn test_compose_block() {
	// given
	let (_, _, shard, _, _, state_handler, _) = test_setup();
	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let signed_top_hashes: Vec<H256> = vec![[94; 32].into(), [1; 32].into()].to_vec();

	let (mut state, _) = state_handler.load_cloned(&shard).unwrap();
	state.set_block_number(&1);
	let state_hash_before_execution = state.hash();

	// when
	let signed_block = block_composer
		.compose_block(
			&latest_parentchain_header(),
			signed_top_hashes,
			shard,
			state_hash_before_execution,
			&state,
		)
		.unwrap();

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().header().block_number(), 1);
}

fn test_submit_trusted_call_to_top_pool() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, ..) = test_setup();

	let sender = funded_pair();

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	let calls = top_pool_author.get_pending_trusted_calls(shard);

	// then
	assert_eq!(calls[0], trusted_operation);
}

// The TOP pool can hold any TrustedOperation, which at the moment also includes Getters.
// However, in reality we don't submit getters to the TOP pool anymore, they are executed immediately.
// The filter set in the TOP pool author prevents getters from being submitted.
// In this test however, we set the filter to `AllowAllTops`, so getters can be submitted.
// We want to keep this back door open, in case we would want to submit getter into the TOP pool again in the future.
fn test_submit_trusted_getter_to_top_pool() {
	// given
	let (top_pool_author, _, shard, _, shielding_key, ..) = test_setup();

	let sender = funded_pair();

	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();

	let getters = top_pool_author.get_pending_trusted_getters(shard);

	// then
	assert_eq!(getters[0], TrustedOperation::get(Getter::trusted(signed_getter)));
}

fn test_differentiate_getter_and_call_works() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, ..) = test_setup();

	// create accounts
	let sender = funded_pair();

	let signed_getter =
		TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	// when
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();
	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	let calls = top_pool_author.get_pending_trusted_calls(shard);
	let getters = top_pool_author.get_pending_trusted_getters(shard);

	// then
	assert_eq!(calls[0], trusted_operation);
	assert_eq!(getters[0], TrustedOperation::get(Getter::trusted(signed_getter)));
}

fn test_create_block_and_confirmation_works() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	let top_hash = submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result = execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let signed_block = block_composer
		.compose_block(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.state_hash_before_execution,
			&execution_result.state_after_execution,
		)
		.unwrap();

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().header().block_number(), 1);
	assert_eq!(signed_block.block().block_data().signed_top_hashes()[0], top_hash);
}

fn test_create_state_diff() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	let block_composer = BlockComposer::<Block, SignedBlock, _, _>::new(
		test_account(),
		Arc::new(TestStateKeyRepo::new(state_key())),
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let trusted_operation = direct_top(signed_call);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result = execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let signed_block = block_composer
		.compose_block(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.state_hash_before_execution,
			&execution_result.state_after_execution,
		)
		.unwrap();

	let encrypted_state_diff = encrypted_state_diff_from_encrypted(
		signed_block.block().block_data().encrypted_state_diff(),
	);
	let state_diff = encrypted_state_diff.state_update();

	// then
	let sender_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash::<AccountId>(&sender.public().into()));

	let receiver_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash::<AccountId>(&receiver.into()));

	// state diff should consist of the following updates:
	// (last_hash, sidechain block_number, sender_funds, receiver_funds, [no clear, after polkadot_v0.9.26 update], events)
	assert_eq!(state_diff.len(), 6);
	assert_eq!(receiver_acc_info.data.free, 1000);
	assert_eq!(sender_acc_info.data.free, 1000);
}

fn test_executing_call_updates_account_nonce() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	let sender = funded_pair();
	let receiver = unfunded_public();

	let trusted_operation =
		TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard)
			.into_trusted_operation(false);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let mut execution_result =
		execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	let nonce = TestStf::get_account_nonce(
		&mut execution_result.state_after_execution,
		&sender.public().into(),
	);
	assert_eq!(nonce, 1);
}

fn test_call_set_update_parentchain_block() {
	let (_, _, shard, _, _, state_handler, _) = test_setup();
	let (mut state, _) = state_handler.load_cloned(&shard).unwrap();

	let block_number = 3;
	let parent_hash = H256::from([1; 32]);

	let header: Header = HeaderT::new(
		block_number,
		Default::default(),
		Default::default(),
		parent_hash,
		Default::default(),
	);

	TestStf::update_parentchain_block(&mut state, header.clone()).unwrap();

	assert_eq!(header.hash(), state.execute_with(|| Parentchain::block_hash()));
	assert_eq!(parent_hash, state.execute_with(|| Parentchain::parent_hash()));
	assert_eq!(block_number, state.execute_with(|| Parentchain::block_number()));
}

fn test_signature_must_match_public_sender_in_call() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let trusted_operation =
		TrustedCall::balance_transfer(receiver.into(), sender.public().into(), 1000)
			.sign(&sender.clone().into(), 10, &mrenclave, &shard)
			.into_trusted_operation(true);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch = execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	// then
	assert!(!executed_batch.executed_operations[0].is_success());
}

fn test_invalid_nonce_call_is_not_executed() {
	// given
	let (top_pool_author, _, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let trusted_operation =
		TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
			.sign(&sender.clone().into(), 10, &mrenclave, &shard)
			.into_trusted_operation(true);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch = execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	// then
	assert!(!executed_batch.executed_operations[0].is_success());
}

fn test_non_root_shielding_call_is_not_executed() {
	// given
	let (top_pool_author, _state, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	let sender = funded_pair();
	let sender_acc: AccountId = sender.public().into();

	let signed_call = TrustedCall::balance_shield(sender_acc.clone(), sender_acc.clone(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch = execute_trusted_calls(&shard, stf_executor.as_ref(), &top_pool_author);

	// then
	assert!(!executed_batch.executed_operations[0].is_success());
}

fn test_shielding_call_with_enclave_self_is_executed() {
	let (top_pool_author, _state, shard, mrenclave, shielding_key, _, stf_executor) = test_setup();

	let sender = funded_pair();
	let sender_account: AccountId = sender.public().into();
	let enclave_call_signer = enclave_call_signer(&shielding_key);

	let signed_call = TrustedCall::balance_shield(
		enclave_call_signer.public().into(),
		sender_account.clone(),
		1000,
	)
	.sign(&enclave_call_signer.into(), 0, &mrenclave, &shard);
	let trusted_operation = TrustedOperation::indirect_call(signed_call);

	submit_operation_to_top_pool(
		top_pool_author.as_ref(),
		&trusted_operation,
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let executed_batch =
		execute_trusted_calls(&shard, stf_executor.as_ref(), top_pool_author.as_ref());

	// then
	assert_eq!(1, executed_batch.executed_operations.len());
	assert!(executed_batch.executed_operations[0].is_success());
}

pub fn test_retrieve_events() {
	// given
	let (_, mut state, shard, mrenclave, ..) = test_setup();
	let mut opaque_vec = Vec::new();
	let sender = funded_pair();
	let receiver = unendowed_account();
	let transfer_value: u128 = 1_000;
	// Events will only get executed after genesis.
	state.execute_with(|| set_block_number(100));

	// Execute a transfer extrinsic to generate events via the Balance pallet.
	let trusted_call = TrustedCall::balance_transfer(
		sender.public().into(),
		receiver.public().into(),
		transfer_value,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	assert_eq!(TestStf::get_events(&mut state).len(), 3);
}

pub fn test_retrieve_event_count() {
	let (_, mut state, shard, mrenclave, ..) = test_setup();
	let mut opaque_vec = Vec::new();
	let sender = funded_pair();
	let receiver = unendowed_account();
	let transfer_value: u128 = 1_000;
	// Events will only get executed after genesis.
	state.execute_with(|| set_block_number(100));

	// Execute a transfer extrinsic to generate events via the Balance pallet.
	let trusted_call = TrustedCall::balance_transfer(
		sender.public().into(),
		receiver.public().into(),
		transfer_value,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();

	let event_count = TestStf::get_event_count(&mut state);
	assert_eq!(event_count, 3);
}

pub fn test_reset_events() {
	let (_, mut state, shard, mrenclave, ..) = test_setup();
	let mut opaque_vec = Vec::new();
	let sender = funded_pair();
	let receiver = unendowed_account();
	let transfer_value: u128 = 1_000;
	// Events will only get executed after genesis.
	state.execute_with(|| set_block_number(100));
	// Execute a transfer extrinsic to generate events via the Balance pallet.
	let trusted_call = TrustedCall::balance_transfer(
		sender.public().into(),
		receiver.public().into(),
		transfer_value,
	)
	.sign(&sender.clone().into(), 0, &mrenclave, &shard);
	let repo = Arc::new(NodeMetadataRepository::<NodeMetadataMock>::default());
	TestStf::execute_call(&mut state, trusted_call, &mut opaque_vec, repo).unwrap();
	let receiver_acc_info = TestStf::get_account_data(&mut state, &receiver.public().into());
	assert_eq!(receiver_acc_info.free, transfer_value);
	// Ensure that there really have been events generated.
	assert_eq!(TestStf::get_events(&mut state).len(), 3);

	// Remove the events.
	TestStf::reset_events(&mut state);

	// Ensure that the events storage has been cleared.
	assert_eq!(TestStf::get_events(&mut state).len(), 0);
}

fn execute_trusted_calls(
	shard: &ShardIdentifier,
	stf_executor: &TestStfExecutor,
	top_pool_author: &TestTopPoolAuthor,
) -> BatchExecutionResult<State> {
	let top_pool_calls = top_pool_author.get_pending_trusted_calls(*shard);
	let execution_result = stf_executor
		.propose_state_update(
			&top_pool_calls,
			&latest_parentchain_header(),
			&shard,
			Duration::from_millis(600),
			|mut s| {
				s.set_block_number(&s.get_block_number().map_or(1, |n| n + 1));
				s
			},
		)
		.unwrap();
	execution_result
}

// helper functions
/// Decrypt `encrypted` and decode it into `StatePayload`
pub fn encrypted_state_diff_from_encrypted(
	encrypted: &[u8],
) -> StatePayload<SgxExternalitiesDiffType> {
	let mut encrypted_payload: Vec<u8> = encrypted.to_vec();
	let state_key = state_key();
	state_key.decrypt(&mut encrypted_payload).unwrap();
	StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap()
}

pub fn state_key() -> Aes {
	Aes::default()
}

/// Some random account that has no funds in the `Stf`'s `test_genesis` config.
pub fn unfunded_public() -> spEd25519::Public {
	spEd25519::Public::from_raw(*b"asdfasdfadsfasdfasfasdadfadfasdf")
}

pub fn test_account() -> spEd25519::Pair {
	spEd25519::Pair::from_seed(b"42315678901234567890123456789012")
}

/// transforms `call` into `TrustedOperation::direct(call)`
pub fn direct_top(call: TrustedCallSigned) -> TrustedOperation {
	call.into_trusted_operation(true)
}

/// Just some random onchain header
pub fn latest_parentchain_header() -> Header {
	Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default())
}

/// Reads the value at `key_hash` from `state_diff` and decodes it into `D`
pub fn get_from_state_diff<D: Decode>(state_diff: &SgxExternalitiesDiffType, key_hash: &[u8]) -> D {
	// fixme: what's up here with the wrapping??
	state_diff
		.get(key_hash)
		.unwrap()
		.as_ref()
		.map(|d| Decode::decode(&mut d.as_slice()))
		.unwrap()
		.unwrap()
}
