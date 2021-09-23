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
	ocall::OcallApi,
	rpc, state,
	test::{cert_tests::*, mocks::rpc_responder_mock::RpcResponderMock},
	top_pool,
	top_pool::{
		pool::ExtrinsicHash,
		top_pool_container::{GetTopPool, TopPoolContainer},
	},
};
use codec::{Decode, Encode};
use core::ops::Deref;
use ita_stf::{
	stf_sgx::StateHash, stf_sgx_primitives::account_key_hash,
	test_genesis::test_account as funded_pair, AccountInfo, ShardIdentifier, State, StatePayload,
	StateTypeDiff, Stf, TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned,
	TrustedOperation,
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::{
	enclave::MAX_TRUSTED_OPS_EXEC_DURATION,
	node::{BLOCK_CONFIRMED, TEEREX_MODULE},
};
use itp_sgx_crypto::{AesSeal, Rsa3072Seal, ShieldingCrypto, StateCrypto};
use itp_sgx_io::SealedIO;
use itp_storage::storage_value_key;
use itp_types::{Block, Header, MrEnclave, OpaqueCall, SidechainBlockNumber};
use its_primitives::{
	traits::{Block as BlockT, SignedBlock as SignedBlockT},
	types::block::SignedBlock,
};
use jsonrpc_core::futures::executor;
use log::*;
use rpc::{
	api::SideChainApi,
	author::{Author, AuthorApi},
	basic_pool::BasicPool,
};
use sgx_tunittest::*;
use sgx_types::size_t;
use sp_core::{crypto::Pair, ed25519 as spEd25519, hashing::blake2_256, H256};
use sp_runtime::traits::Header as HeaderT;
use std::{string::String, sync::Arc, vec::Vec};

type TestRpcResponder = RpcResponderMock<ExtrinsicHash<SideChainApi<Block>>>;
type TestTopPool = TopPoolContainer<BasicPool<SideChainApi<Block>, Block, TestRpcResponder>>;

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	rsgx_unit_tests!(
		top_pool::base_pool::tests::test_should_import_transaction_to_ready,
		top_pool::base_pool::tests::test_should_not_import_same_transaction_twice,
		top_pool::base_pool::tests::test_should_import_transaction_to_future_and_promote_it_later,
		top_pool::base_pool::tests::test_should_promote_a_subgraph,
		top_pool::base_pool::tests::test_should_handle_a_cycle,
		top_pool::base_pool::tests::test_can_track_heap_size,
		top_pool::base_pool::tests::test_should_handle_a_cycle_with_low_priority,
		top_pool::base_pool::tests::test_should_remove_invalid_transactions,
		top_pool::base_pool::tests::test_should_prune_ready_transactions,
		top_pool::base_pool::tests::test_transaction_debug,
		top_pool::base_pool::tests::test_transaction_propagation,
		top_pool::base_pool::tests::test_should_reject_future_transactions,
		top_pool::base_pool::tests::test_should_clear_future_queue,
		top_pool::base_pool::tests::test_should_accept_future_transactions_when_explicitly_asked_to,
		top_pool::primitives::tests::test_h256,
		top_pool::pool::tests::test_should_validate_and_import_transaction,
		top_pool::pool::tests::test_should_reject_if_temporarily_banned,
		top_pool::pool::tests::test_should_notify_about_pool_events,
		top_pool::pool::tests::test_should_clear_stale_transactions,
		top_pool::pool::tests::test_should_ban_mined_transactions,
		//FIXME: This test sometimes fails, sometimes succeeds..
		//top_pool::pool::test_should_limit_futures,
		top_pool::pool::tests::test_should_error_if_reject_immediately,
		top_pool::pool::tests::test_should_reject_transactions_with_no_provides,
		top_pool::ready::tests::test_should_replace_transaction_that_provides_the_same_tag,
		top_pool::ready::tests::test_should_replace_multiple_transactions_correctly,
		top_pool::ready::tests::test_should_return_best_transactions_in_correct_order,
		top_pool::ready::tests::test_should_order_refs,
		top_pool::rotator::tests::test_should_not_ban_if_not_stale,
		top_pool::rotator::tests::test_should_ban_stale_extrinsic,
		top_pool::rotator::tests::test_should_clear_banned,
		top_pool::rotator::tests::test_should_garbage_collect,
		top_pool::tracked_map::tests::test_basic,
		state::tests::test_write_and_load_state_works,
		state::tests::test_sgx_state_decode_encode_works,
		state::tests::test_encrypt_decrypt_state_type_works,
		test_compose_block_and_confirmation,
		test_submit_trusted_call_to_top_pool,
		test_submit_trusted_getter_to_top_pool,
		test_differentiate_getter_and_call_works,
		test_create_block_and_confirmation_works,
		// needs node to be running.. unit tests?
		// test_ocall_worker_request,
		test_create_state_diff,
		test_executing_call_updates_account_nonce,
		test_invalid_nonce_call_is_not_executed,
		test_non_root_shielding_call_is_not_executed,
		ita_stf::stf_sgx::tests::apply_state_diff_works,
		ita_stf::stf_sgx::tests::apply_state_diff_returns_storage_hash_mismatch_err,
		ita_stf::stf_sgx::tests::apply_state_diff_returns_invalid_storage_diff_err,
		rpc::worker_api_direct::tests::sidechain_import_block_is_ok,
		rpc::worker_api_direct::tests::sidechain_import_block_returns_invalid_param_err,
		rpc::worker_api_direct::tests::sidechain_import_block_returns_decode_err,
		//
		// mra cert tests
		test_verify_mra_cert_should_work,
		test_verify_wrong_cert_is_err,
		test_given_wrong_platform_info_when_verifying_attestation_report_then_return_error,
		//
		// these unit test (?) need an ipfs node running..
		//ipfs::test_creates_ipfs_content_struct_works,
		//ipfs::test_verification_ok_for_correct_content,
		//ipfs::test_verification_fails_for_incorrect_content,
		//test_ocall_read_write_ipfs,
	)
}

#[allow(unused)]
pub fn ensure_no_empty_shard_directory_exists() {
	// ensure no empty states are within directory (created with init-shard)
	// otherwise an 'index out of bounds: the len is x but the index is x'
	// error will be thrown
	let shards = state::list_shards().unwrap();
	for shard in shards {
		if !state::exists(&shard) {
			state::init_shard(&shard).unwrap();
		}
	}
}

#[allow(unused)]
fn test_compose_block_and_confirmation() {
	// given
	ensure_no_empty_shard_directory_exists();

	let (mut state, shard) = init_state();
	let signed_top_hashes: Vec<H256> = vec![[94; 32].into(), [1; 32].into()].to_vec();

	Stf::update_sidechain_block_number(&mut state, 3);

	// when
	let (opaque_call, signed_block) = crate::compose_block_and_confirmation::<Block, SignedBlock>(
		&latest_onchain_header(),
		signed_top_hashes,
		shard,
		state.hash(),
		&mut state,
	)
	.unwrap();

	let expected_call = OpaqueCall::from_tuple(&(
		[TEEREX_MODULE, BLOCK_CONFIRMED],
		shard,
		blake2_256(&signed_block.block().encode()),
	));

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 4);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_submit_trusted_call_to_top_pool() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.into(), 0, &mrenclave, &shard);

	// when
	submit_top_to_top_pool(&top_pool, direct_top(signed_call.clone()), shard);

	// get pending extrinsics
	let (calls, _) = get_pending_tops_separated(&top_pool, shard);

	// then
	let call_one = format! {"{:?}", calls[0]};
	let call_two = format! {"{:?}", signed_call};
	assert_eq!(call_one, call_two);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_submit_trusted_getter_to_top_pool() {
	// given
	ensure_no_empty_shard_directory_exists();

	let (mut state, shard) = init_state();
	let top_pool = test_top_pool();

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_getter = TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());

	submit_top_to_top_pool(&top_pool, signed_getter.clone().into(), shard);

	let (_, getters) = get_pending_tops_separated(&top_pool, shard);

	// then
	let getter_one = format! {"{:?}", getters[0]};
	let getter_two = format! {"{:?}", signed_getter};
	assert_eq!(getter_one, getter_two);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_differentiate_getter_and_call_works() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let index = get_current_shard_index(&shard);

	let signed_getter =
		TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());

	let signed_call =
		TrustedCall::balance_set_balance(sender.public().into(), sender.public().into(), 42, 42)
			.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	submit_top_to_top_pool(&top_pool, signed_getter.clone().into(), shard);
	submit_top_to_top_pool(&top_pool, direct_top(signed_call.clone()), shard);

	// when
	let (calls, getters) = get_pending_tops_separated(&top_pool, shard);

	// then
	let getter_one = format! {"{:?}", getters[0]};
	let getter_two = format! {"{:?}", signed_getter};
	let call_one = format! {"{:?}", calls[0]};
	let call_two = format! {"{:?}", signed_call};
	assert_eq!(call_one, call_two);
	assert_eq!(getter_one, getter_two);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
#[allow(unused_assignments)]
fn test_create_block_and_confirmation_works() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	assert_eq!(Stf::get_sidechain_block_number(&mut state).unwrap(), 0);

	let sender = funded_pair();
	let receiver = unfunded_public();

	let index = get_current_shard_index(&shard);

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	let top_hash = submit_top_to_top_pool(&top_pool, direct_top(signed_call), shard);

	// when
	let (confirm_calls, signed_blocks) =
		crate::exec_tops_for_all_shards::<Block, SignedBlock, _, _>(
			&OcallApi,
			&top_pool,
			&latest_onchain_header(),
			MAX_TRUSTED_OPS_EXEC_DURATION,
		)
		.unwrap();

	debug!("got {} signed block(s)", signed_blocks.len());

	let signed_block = signed_blocks[index].clone();
	let mut opaque_call = confirm_calls[index].clone();

	let expected_call = OpaqueCall::from_tuple(&(
		[TEEREX_MODULE, BLOCK_CONFIRMED],
		shard,
		blake2_256(&signed_block.block().encode()),
	));

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 1);
	assert_eq!(signed_block.block().signed_top_hashes()[0], top_hash);
	assert!(opaque_call.encode().starts_with(&expected_call.encode()));

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_create_state_diff() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	let receiver = unfunded_public();
	let sender = funded_pair();

	let index = get_current_shard_index(&shard);

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	submit_top_to_top_pool(&top_pool, direct_top(signed_call), shard);

	// when
	let (_, signed_blocks) = crate::exec_tops_for_all_shards::<Block, SignedBlock, _, _>(
		&OcallApi,
		&top_pool,
		&latest_onchain_header(),
		MAX_TRUSTED_OPS_EXEC_DURATION,
	)
	.unwrap();

	let mut encrypted_payload: Vec<u8> = signed_blocks[index].block().state_payload().to_vec();
	AesSeal::unseal().map(|key| key.decrypt(&mut encrypted_payload)).unwrap();
	let state_payload = StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap();
	let state_diff = state_payload.state_update();

	// then
	let sender_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&sender.public().into()));

	let receiver_acc_info: AccountInfo =
		get_from_state_diff(&state_diff, &account_key_hash(&receiver.into()));

	let block_num: SidechainBlockNumber =
		get_from_state_diff(&state_diff, &storage_value_key("System", "Number"));

	assert_eq!(state_diff.len(), 3);
	assert_eq!(receiver_acc_info.data.free, 1000);
	assert_eq!(sender_acc_info.data.free, 1000);
	assert_eq!(block_num, 1);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_executing_call_updates_account_nonce() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 0, &mrenclave, &shard);

	submit_top_to_top_pool(&top_pool, direct_top(signed_call), shard);

	// when
	let (_, signed_blocks) = crate::exec_tops_for_all_shards::<Block, SignedBlock, _, _>(
		&OcallApi,
		&top_pool,
		&latest_onchain_header(),
		MAX_TRUSTED_OPS_EXEC_DURATION,
	)
	.unwrap();

	// then
	let mut state = state::load(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut state, &sender.public().into());
	assert_eq!(nonce, 1);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_invalid_nonce_call_is_not_executed() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	// create accounts
	let sender = funded_pair();
	let receiver = unfunded_public();

	let signed_call = TrustedCall::balance_transfer(sender.public().into(), receiver.into(), 1000)
		.sign(&sender.clone().into(), 10, &mrenclave, &shard);

	submit_top_to_top_pool(&top_pool, direct_top(signed_call), shard);

	// when
	let (_, signed_blocks) = crate::exec_tops_for_all_shards::<Block, SignedBlock, _, _>(
		&OcallApi,
		&top_pool,
		&latest_onchain_header(),
		MAX_TRUSTED_OPS_EXEC_DURATION,
	)
	.unwrap();

	// then
	let mut updated_state = state::load(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut updated_state, &sender.public().into());
	assert_eq!(nonce, 0);

	let sender_data = Stf::account_data(&mut updated_state, &sender.public().into()).unwrap();
	assert_eq!(sender_data.free, 2000);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_non_root_shielding_call_is_not_executed() {
	// given
	let (top_pool, mut state, shard, mrenclave) = test_setup();

	let sender = funded_pair();
	let sender_acc = sender.public().into();

	let funds_old = Stf::account_data(&mut state, &sender_acc).unwrap().free;

	let signed_call = TrustedCall::balance_shield(sender_acc.clone(), sender_acc.clone(), 1000)
		.sign(&sender.into(), 0, &mrenclave, &shard);

	submit_top_to_top_pool(&top_pool, direct_top(signed_call), shard);

	// when
	let (_, signed_blocks) = crate::exec_tops_for_all_shards::<Block, SignedBlock, _, _>(
		&OcallApi,
		&top_pool,
		&latest_onchain_header(),
		MAX_TRUSTED_OPS_EXEC_DURATION,
	)
	.unwrap();

	// then
	let mut updated_state = state::load(&shard).unwrap();

	let nonce = Stf::account_nonce(&mut updated_state, &sender_acc);
	let funds_new = Stf::account_data(&mut updated_state, &sender_acc).unwrap().free;

	assert_eq!(nonce, 0);
	assert_eq!(funds_new, funds_old);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

fn get_current_shard_index(shard: &ShardIdentifier) -> usize {
	let shards = state::list_shards().unwrap();
	let mut index = 0;
	for s in shards.into_iter() {
		if s == *shard {
			break
		}
		index += 1;
	}

	debug!("current shard index is {}", index);

	index
}

fn init_state() -> (State, ShardIdentifier) {
	let shard = ShardIdentifier::default();

	// ensure that state starts empty
	state::init_shard(&shard).unwrap();

	(Stf::init_state(), shard)
}

fn test_top_pool() -> TestTopPool {
	let chain_api = Arc::new(SideChainApi::<Block>::new());
	let top_pool = TopPoolContainer::new(BasicPool::create(
		Default::default(),
		chain_api,
		Arc::new(TestRpcResponder::new()),
	));

	top_pool
}

fn test_setup() -> (TestTopPool, State, ShardIdentifier, MrEnclave) {
	ensure_no_empty_shard_directory_exists();

	let (state, shard) = init_state();
	let top_pool = test_top_pool();
	let mrenclave = OcallApi.get_mrenclave_of_self().unwrap().m;

	(top_pool, state, shard, mrenclave)
}

fn unfunded_public() -> spEd25519::Public {
	spEd25519::Public::from_raw(*b"asdfasdfadsfasdfasfasdadfadfasdf")
}

fn direct_top(call: TrustedCallSigned) -> TrustedOperation {
	call.into_trusted_operation(true)
}

fn latest_onchain_header() -> Header {
	Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default())
}

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

fn submit_top_to_top_pool<P: GetTopPool>(
	top_pool: &P,
	trusted_op: TrustedOperation,
	shard: ShardIdentifier,
) -> H256 {
	let pool_mutex = top_pool.get().unwrap();
	let pool_guard = pool_mutex.lock().unwrap();
	let pool = Arc::new(pool_guard.deref());
	let author = Arc::new(Author::new(pool.clone()));

	let encrypted_top = Rsa3072Seal::unseal()
		.map(|key| key.encrypt(&trusted_op.encode()))
		.unwrap()
		.unwrap();

	// submit trusted call to top pool
	let result = async { author.submit_top(encrypted_top.clone(), shard).await };
	executor::block_on(result).unwrap()
}

fn get_pending_tops_separated<P: GetTopPool>(
	top_pool: &P,
	shard: ShardIdentifier,
) -> (Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>) {
	let pool_mutex = top_pool.get().unwrap();
	let pool_guard = pool_mutex.lock().unwrap();
	let pool = Arc::new(pool_guard.deref());
	let author = Arc::new(Author::new(pool.clone()));

	author.get_pending_tops_separated(shard).unwrap()
}
