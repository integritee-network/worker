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
	attestation,
	ocall::OcallApi,
	rpc,
	sidechain_block_composer::{BlockComposer, ComposeBlockAndConfirmation},
	sync::tests::{enclave_rw_lock_works, sidechain_rw_lock_works},
	test::{cert_tests::*, mocks::rpc_responder_mock::RpcResponderMock},
	top_pool_operation_executor::{ExecuteCallsOnTopPool, TopPoolOperationExecutor},
};
use codec::{Decode, Encode};
use ita_stf::{
	helpers::account_key_hash, test_genesis::test_account as funded_pair, AccountInfo,
	ShardIdentifier, State, StatePayload, StateTypeDiff, Stf, TrustedCall, TrustedCallSigned,
	TrustedGetter, TrustedOperation,
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	enclave::MAX_TRUSTED_OPS_EXEC_DURATION,
	node::{PROCESSED_PARENTCHAIN_BLOCK, PROPOSED_SIDECHAIN_BLOCK, TEEREX_MODULE},
};
use itp_sgx_crypto::{Aes, StateCrypto};
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::handle_state::HandleState;
use itp_test::mock::{
	handle_state_mock, handle_state_mock::HandleStateMock,
	shielding_crypto_mock::ShieldingCryptoMock,
};
use itp_types::{Block, Header, MrEnclave, OpaqueCall};
use its_sidechain::{
	primitives::{
		traits::{Block as BlockT, SignedBlock as SignedBlockT},
		types::block::SignedBlock,
	},
	state::{LastBlockExt, SidechainDB, SidechainState, SidechainSystemExt},
	top_pool::{basic_pool::BasicPool, pool::ExtrinsicHash},
	top_pool_rpc_author::{
		api::SidechainApi,
		author::Author,
		author_tests,
		test_utils::{get_pending_tops_separated, submit_operation_to_top_pool},
		top_filter::AllowAllTopsFilter,
	},
};
use sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
use sgx_tunittest::*;
use sgx_types::size_t;
use sp_core::{crypto::Pair, ed25519 as spEd25519, hashing::blake2_256, H256};
use sp_runtime::traits::Header as HeaderT;
use std::{string::String, sync::Arc, vec::Vec};

type TestRpcResponder = RpcResponderMock<ExtrinsicHash<SidechainApi<Block>>>;
type TestTopPool = BasicPool<SidechainApi<Block>, Block, TestRpcResponder>;
type TestRpcAuthor = Author<TestTopPool, AllowAllTopsFilter, HandleStateMock, ShieldingCryptoMock>;

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	rsgx_unit_tests!(
		attestation::tests::decode_spid_works,
		itp_stf_state_handler::tests::test_write_and_load_state_works,
		itp_stf_state_handler::tests::test_sgx_state_decode_encode_works,
		itp_stf_state_handler::tests::test_encrypt_decrypt_state_type_works,
		itp_stf_state_handler::tests::test_write_access_locks_read_until_finished,
		itp_stf_state_handler::tests::test_ensure_subsequent_state_loads_have_same_hash,
		test_compose_block_and_confirmation,
		test_submit_trusted_call_to_top_pool,
		test_submit_trusted_getter_to_top_pool,
		test_differentiate_getter_and_call_works,
		test_create_block_and_confirmation_works,
		ensure_empty_extrinsic_vec_triggers_zero_filled_merkle_root,
		ensure_non_empty_extrinsic_vec_triggers_non_zero_merkle_root,
		// needs node to be running.. unit tests?
		// test_ocall_worker_request,
		test_create_state_diff,
		test_executing_call_updates_account_nonce,
		test_invalid_nonce_call_is_not_executed,
		test_non_root_shielding_call_is_not_executed,
		rpc::worker_api_direct::tests::test_given_io_handler_methods_then_retrieve_all_names_as_string,
		author_tests::top_encryption_works,
		author_tests::submitting_to_author_inserts_in_pool,
		author_tests::submitting_call_to_author_when_top_is_filtered_returns_error,
		author_tests::submitting_getter_to_author_when_top_is_filtered_inserts_in_pool,
		handle_state_mock::tests::initialized_shards_list_is_empty,
		handle_state_mock::tests::shard_exists_after_inserting,
		handle_state_mock::tests::load_initialized_inserts_default_state,
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
		// these unit test (?) need an ipfs node running..
		// ipfs::test_creates_ipfs_content_struct_works,
		// ipfs::test_verification_ok_for_correct_content,
		// ipfs::test_verification_fails_for_incorrect_content,
		// test_ocall_read_write_ipfs,
	)
}

fn test_compose_block_and_confirmation() {
	// given
	let (rpc_author, _, shard, _, _, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let block_composer = BlockComposer::<Block, SignedBlock, _, _, _, _>::new(
		test_account(),
		state_key(),
		rpc_author.clone(),
		stf_executor,
	);

	let signed_top_hashes: Vec<H256> = vec![[94; 32].into(), [1; 32].into()].to_vec();

	let (lock, state) = state_handler.load_for_mutation(&shard).unwrap();
	let mut db = SidechainDB::<SignedBlock, _>::new(state);
	db.set_block_number(&1);
	let previous_state_hash = db.state_hash();
	state_handler.write(db.ext, lock, &shard).unwrap();

	// when
	let (opaque_call, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			signed_top_hashes,
			shard,
			previous_state_hash,
		)
		.unwrap();

	// then
	let expected_call = OpaqueCall::from_tuple(&(
		[TEEREX_MODULE, PROPOSED_SIDECHAIN_BLOCK],
		shard,
		blake2_256(&signed_block.block().encode()),
	));

	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 1);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));
}

fn test_submit_trusted_call_to_top_pool() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, _) = test_setup();

	let sender = funded_pair();

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.into(), 0, &mrenclave, &shard);

	// when
	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call.clone()),
		&shielding_key,
		shard,
	)
	.unwrap();

	let (calls, _) = get_pending_tops_separated(rpc_author.as_ref(), shard);

	// then
	assert_eq!(calls[0], signed_call);
}

fn test_submit_trusted_getter_to_top_pool() {
	// given
	let (rpc_author, _, shard, _, shielding_key, _) = test_setup();

	let sender = funded_pair();

	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());

	// when
	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();

	let (_, getters) = get_pending_tops_separated(rpc_author.as_ref(), shard);

	// then
	assert_eq!(getters[0], signed_getter);
}

fn test_differentiate_getter_and_call_works() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, _) = test_setup();

	// create accounts
	let sender = funded_pair();

	let signed_getter =
		TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	// when
	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&signed_getter.clone().into(),
		&shielding_key,
		shard,
	)
	.unwrap();
	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call.clone()),
		&shielding_key,
		shard,
	)
	.unwrap();

	let (calls, getters) = get_pending_tops_separated(rpc_author.as_ref(), shard);

	// then
	assert_eq!(calls[0], signed_call);
	assert_eq!(getters[0], signed_getter);
}

fn test_create_block_and_confirmation_works() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_executor = TopPoolOperationExecutor::<Block, SignedBlock, _, _>::new(
		rpc_author.clone(),
		stf_executor.clone(),
	);
	let block_composer = BlockComposer::<Block, SignedBlock, _, _, _, _>::new(
		test_account(),
		state_key(),
		rpc_author.clone(),
		stf_executor,
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	let top_hash = submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result = top_pool_executor
		.execute_trusted_calls(&latest_parentchain_header(), shard, MAX_TRUSTED_OPS_EXEC_DURATION)
		.unwrap();

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let (opaque_call, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.previous_state_hash,
		)
		.unwrap();

	// then
	let expected_call = OpaqueCall::from_tuple(&(
		[TEEREX_MODULE, PROPOSED_SIDECHAIN_BLOCK],
		shard,
		blake2_256(&signed_block.block().encode()),
	));

	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 1);
	assert_eq!(signed_block.block().signed_top_hashes()[0], top_hash);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));

	let db = SidechainDB::new(state_handler.load_initialized(&shard).unwrap());

	assert_eq!(db.get_last_block(), Some(signed_block.block().clone()));
}

fn test_create_state_diff() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_executor = TopPoolOperationExecutor::<Block, SignedBlock, _, _>::new(
		rpc_author.clone(),
		stf_executor.clone(),
	);
	let block_composer = BlockComposer::<Block, SignedBlock, _, _, _, _>::new(
		test_account(),
		state_key(),
		rpc_author.clone(),
		stf_executor,
	);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let execution_result = top_pool_executor
		.execute_trusted_calls(&latest_parentchain_header(), shard, MAX_TRUSTED_OPS_EXEC_DURATION)
		.unwrap();

	let executed_operation_hashes =
		execution_result.get_executed_operation_hashes().iter().copied().collect();

	let (_, signed_block) = block_composer
		.compose_block_and_confirmation(
			&latest_parentchain_header(),
			executed_operation_hashes,
			shard,
			execution_result.previous_state_hash,
		)
		.unwrap();

	let state_payload = state_payload_from_encrypted(signed_block.block().state_payload());
	let state_diff = state_payload.state_update();

	// then
	let sender_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&sender.public().into()));

	let receiver_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&receiver.into()));

	// (last_hash, block_number, timestamp, sender_funds, receiver_funds)
	assert_eq!(state_diff.len(), 5);
	assert_eq!(receiver_acc_info.data.free, 1000);
	assert_eq!(sender_acc_info.data.free, 1000);

	// Fixme: Fails #421
	// assert_eq!(apriori_hash, state_payload.state_hash_apriori());
}

fn test_executing_call_updates_account_nonce() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_executor =
		TopPoolOperationExecutor::<Block, SignedBlock, _, _>::new(rpc_author.clone(), stf_executor);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let _ = top_pool_executor
		.execute_trusted_calls(&latest_parentchain_header(), shard, MAX_TRUSTED_OPS_EXEC_DURATION)
		.unwrap();

	// then
	let mut state = state_handler.load_initialized(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut state, &sender.public().into());
	assert_eq!(nonce, 1);
}

fn test_invalid_nonce_call_is_not_executed() {
	// given
	let (rpc_author, _, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_executor =
		TopPoolOperationExecutor::<Block, SignedBlock, _, _>::new(rpc_author.clone(), stf_executor);

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 10, &mrenclave, &shard);

	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let _ = top_pool_executor
		.execute_trusted_calls(&latest_parentchain_header(), shard, MAX_TRUSTED_OPS_EXEC_DURATION)
		.unwrap();

	// then
	let mut updated_state = state_handler.load_initialized(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut updated_state, &sender.public().into());
	assert_eq!(nonce, 0);

	let sender_data = Stf::account_data(&mut updated_state, &sender.public().into()).unwrap();
	assert_eq!(sender_data.free, 2000);
}

fn test_non_root_shielding_call_is_not_executed() {
	// given
	let (rpc_author, mut state, shard, mrenclave, shielding_key, state_handler) = test_setup();
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let top_pool_executor =
		TopPoolOperationExecutor::<Block, SignedBlock, _, _>::new(rpc_author.clone(), stf_executor);

	let sender = funded_pair();
	let sender_acc = sender.public().into();

	let funds_old = Stf::account_data(&mut state, &sender_acc).unwrap().free;

	let signed_call = TrustedCall::balance_shield(sender_acc.clone(), sender_acc.clone(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	submit_operation_to_top_pool(
		rpc_author.as_ref(),
		&direct_top(signed_call),
		&shielding_key,
		shard,
	)
	.unwrap();

	// when
	let _ = top_pool_executor
		.execute_trusted_calls(&latest_parentchain_header(), shard, MAX_TRUSTED_OPS_EXEC_DURATION)
		.unwrap();

	// then
	let mut updated_state = state_handler.load_initialized(&shard).unwrap();

	let nonce = Stf::account_nonce(&mut updated_state, &sender_acc);
	let funds_new = Stf::account_data(&mut updated_state, &sender_acc).unwrap().free;

	assert_eq!(nonce, 0);
	assert_eq!(funds_new, funds_old);
}

fn ensure_empty_extrinsic_vec_triggers_zero_filled_merkle_root() {
	// given
	let block_hash = H256::from([1; 32]);
	let extrinsics = Vec::new();
	let expected_call =
		([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, H256::default()).encode();

	// when
	let call = crate::create_processed_parentchain_block_call(block_hash, extrinsics);

	// then
	assert_eq!(call.0, expected_call);
}

fn ensure_non_empty_extrinsic_vec_triggers_non_zero_merkle_root() {
	// given
	let block_hash = H256::from([1; 32]);
	let extrinsics = vec![H256::from([4; 32]), H256::from([9; 32])];
	let zero_root_call =
		([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, H256::default()).encode();

	// when
	let call = crate::create_processed_parentchain_block_call(block_hash, extrinsics);

	// then
	assert_ne!(call.0, zero_root_call);
}

/// returns an empty `State` with the corresponding `ShardIdentifier`
fn init_state<S: HandleState<StateT = SgxExternalities>>(
	state_handler: &S,
) -> (State, ShardIdentifier) {
	let shard = ShardIdentifier::default();

	let (lock, _) = state_handler.load_for_mutation(&shard).unwrap();

	let mut state = Stf::init_state();
	state.prune_state_diff();

	state_handler.write(state.clone(), lock, &shard).unwrap();

	(state, shard)
}

fn test_top_pool() -> TestTopPool {
	let chain_api = Arc::new(SidechainApi::<Block>::new());
	let top_pool =
		BasicPool::create(Default::default(), chain_api, Arc::new(TestRpcResponder::new()));

	top_pool
}

/// Decrypt `encrypted` and decode it into `StatePayload`
fn state_payload_from_encrypted(encrypted: &[u8]) -> StatePayload {
	let mut encrypted_payload: Vec<u8> = encrypted.to_vec();
	let state_key = state_key();
	state_key.decrypt(&mut encrypted_payload).unwrap();
	StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap()
}

fn state_key() -> Aes {
	Aes::default()
}

/// Returns all the things that are commonly used in tests and runs
/// `ensure_no_empty_shard_directory_exists`
fn test_setup() -> (
	Arc<TestRpcAuthor>,
	State,
	ShardIdentifier,
	MrEnclave,
	ShieldingCryptoMock,
	Arc<HandleStateMock>,
) {
	let state_handler = Arc::new(HandleStateMock::default());
	let (state, shard) = init_state(state_handler.as_ref());
	let top_pool = test_top_pool();
	let mrenclave = OcallApi.get_mrenclave_of_self().unwrap().m;

	let encryption_key = ShieldingCryptoMock::default();

	(
		Arc::new(TestRpcAuthor::new(
			Arc::new(top_pool),
			AllowAllTopsFilter,
			state_handler.clone(),
			encryption_key.clone(),
		)),
		state,
		shard,
		mrenclave,
		encryption_key,
		state_handler,
	)
}

/// Some random account that has no funds in the `Stf`'s `test_genesis` config.
fn unfunded_public() -> spEd25519::Public {
	spEd25519::Public::from_raw(*b"asdfasdfadsfasdfasfasdadfadfasdf")
}

fn test_account() -> spEd25519::Pair {
	spEd25519::Pair::from_seed(b"42315678901234567890123456789012")
}

/// transforms `call` into `TrustedOperation::direct(call)`
fn direct_top(call: TrustedCallSigned) -> TrustedOperation {
	call.into_trusted_operation(true)
}

/// Just some random onchain header
fn latest_parentchain_header() -> Header {
	Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default())
}

/// Reads the value at `key_hash` from `state_diff` and decodes it into `D`
fn get_from_state_diff<D: Decode>(state_diff: &StateTypeDiff, key_hash: &[u8]) -> D {
	// fixme: what's up here with the wrapping??
	state_diff
		.get(key_hash)
		.unwrap()
		.as_ref()
		.map(|d| Decode::decode(&mut d.as_slice()))
		.unwrap()
		.unwrap()
}
