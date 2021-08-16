/*
	Copyright 2019 Supercomputing Systems AG
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
	aes,
	ed25519::Ed25519,
	ocall::ocall_component_factory::{OCallComponentFactory, OCallComponentFactoryTrait},
	rpc, rsa3072, state,
	test::{cert_tests::*, mocks::enclave_rpc_ocall_mock::EnclaveRpcOCallMock},
	top_pool, Timeout,
};
use chain_relay::{Block, Header};
use codec::{Decode, Encode};
use core::ops::Deref;
use jsonrpc_core::futures::executor;
use log::*;
use rpc::{
	api::SideChainApi,
	author::{Author, AuthorApi},
	basic_pool::BasicPool,
};
use sgx_externalities::SgxExternalitiesTypeTrait;
use sgx_tunittest::*;
use sgx_types::size_t;
use sp_core::{crypto::Pair, ed25519 as spEd25519, hashing::blake2_256, H256};
use sp_runtime::traits::Header as HeaderT;
use std::{
	string::String,
	sync::Arc,
	time::{SystemTime, UNIX_EPOCH},
	untrusted::time::SystemTimeEx,
	vec::Vec,
};
use substratee_ocall_api::EnclaveAttestationOCallApi;
use substratee_settings::{
	enclave::GETTER_TIMEOUT,
	node::{BLOCK_CONFIRMED, SUBSTRATEE_REGISTRY_MODULE},
};
use substratee_sgx_io::SealIO;
use substratee_sidechain_primitives::traits::{Block as BlockT, SignedBlock as SignedBlockT};
use substratee_stf::{
	AccountInfo, ShardIdentifier, StatePayload, StateTypeDiff as StfStateTypeDiff, Stf,
	TrustedCall, TrustedGetter, TrustedOperation,
};
use substratee_storage::storage_value_key;

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
		test_time_is_overdue,
		test_time_is_not_overdue,
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
		substratee_stf::stf_sgx::tests::apply_state_diff_works,
		substratee_stf::stf_sgx::tests::apply_state_diff_returns_storage_hash_mismatch_err,
		substratee_stf::stf_sgx::tests::apply_state_diff_returns_invalid_storage_diff_err,
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
fn test_time_is_overdue() {
	// given
	let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	// when
	let before_start_time = (start_time * 1000 - GETTER_TIMEOUT) / 1000;
	let time_has_run_out = crate::time_is_overdue(Timeout::Getter, before_start_time);
	// then
	assert!(time_has_run_out)
}

#[allow(unused)]
fn test_time_is_not_overdue() {
	// given
	let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	// when
	let time_has_run_out = crate::time_is_overdue(Timeout::Call, start_time);
	// then
	assert!(!time_has_run_out)
}

#[allow(unused)]
fn test_compose_block_and_confirmation() {
	// given
	ensure_no_empty_shard_directory_exists();
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let call_hash: H256 = [94; 32].into();
	let call_hash_two: H256 = [1; 32].into();
	let signed_top_hashes = [call_hash, call_hash_two].to_vec();
	let shard = ShardIdentifier::default();
	let state_hash_apriori: H256 = [199; 32].into();
	// ensure state starts empty
	state::init_shard(&shard).unwrap();
	let mut state = Stf::init_state();
	Stf::update_sidechain_block_number(&mut state, 3);

	// when
	let (opaque_call, signed_block) = crate::compose_block_and_confirmation(
		latest_onchain_header,
		signed_top_hashes,
		shard,
		state_hash_apriori,
		&mut state,
	)
	.unwrap();
	let xt_block_encoded = [SUBSTRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED].encode();
	let block_hash_encoded = blake2_256(&signed_block.block().encode()).encode();
	let mut opaque_call_vec = opaque_call.0;

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 4);
	assert!(opaque_call_vec.starts_with(&xt_block_encoded));
	let mut stripped_opaque_call = opaque_call_vec.split_off(xt_block_encoded.len());
	assert!(stripped_opaque_call.starts_with(&shard.encode()));
	let stripped_opaque_call = stripped_opaque_call.split_off(shard.encode().len());
	assert!(stripped_opaque_call.starts_with(&block_hash_encoded));

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_submit_trusted_call_to_top_pool() {
	// given
	ensure_no_empty_shard_directory_exists();

	// create top pool
	let api: Arc<SideChainApi<Block>> = Arc::new(SideChainApi::new());
	let tx_pool: BasicPool<SideChainApi<Block>, Block, EnclaveRpcOCallMock> =
		BasicPool::create(Default::default(), api);
	let author = Author::new(Arc::new(&tx_pool));

	// create trusted call signed
	let nonce = 0;
	let mrenclave = [0u8; 32];
	let shard = ShardIdentifier::default();
	// ensure state starts empty
	state::init_shard(&shard).unwrap();
	Stf::init_state();
	let signer_pair = Ed25519::unseal().unwrap();
	let call = TrustedCall::balance_set_balance(
		signer_pair.public().into(),
		signer_pair.public().into(),
		42,
		42,
	);
	let signed_call = call.sign(&signer_pair.into(), nonce, &mrenclave, &shard);
	let trusted_operation: TrustedOperation = signed_call.clone().into_trusted_operation(true);
	// encrypt call
	let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
	let mut encrypted_top: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
		.unwrap();

	// when

	// submit trusted call to top pool
	let result = async { author.submit_top(encrypted_top.clone(), shard).await };
	executor::block_on(result).unwrap();

	// get pending extrinsics
	let (calls, _) = author.get_pending_tops_separated(shard).unwrap();

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

	// create top pool
	let api: Arc<SideChainApi<Block>> = Arc::new(SideChainApi::new());
	let tx_pool: BasicPool<SideChainApi<Block>, Block, EnclaveRpcOCallMock> =
		BasicPool::create(Default::default(), api);
	let author = Author::new(Arc::new(&tx_pool));

	// create trusted getter signed
	let shard = ShardIdentifier::default();
	// ensure state starts empty
	state::init_shard(&shard).unwrap();
	Stf::init_state();
	let signer_pair = Ed25519::unseal().unwrap();
	let getter = TrustedGetter::free_balance(signer_pair.public().into());
	let signed_getter = getter.sign(&signer_pair.into());
	let trusted_operation: TrustedOperation = signed_getter.clone().into();
	// encrypt call
	let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
	let mut encrypted_top: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
		.unwrap();

	// when

	// submit top to pool
	let result = async { author.submit_top(encrypted_top.clone(), shard).await };
	executor::block_on(result).unwrap();

	// get pending extrinsics
	let (_, getters) = author.get_pending_tops_separated(shard).unwrap();

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
	ensure_no_empty_shard_directory_exists();

	// create top pool
	let api: Arc<SideChainApi<Block>> = Arc::new(SideChainApi::new());
	let tx_pool: BasicPool<SideChainApi<Block>, Block, EnclaveRpcOCallMock> =
		BasicPool::create(Default::default(), api);
	let author = Author::new(Arc::new(&tx_pool));
	// create trusted getter signed
	let shard = ShardIdentifier::default();
	// ensure state starts empty
	state::init_shard(&shard).unwrap();
	Stf::init_state();

	let signer_pair = Ed25519::unseal().unwrap();
	let getter = TrustedGetter::free_balance(signer_pair.public().into());
	let signed_getter = getter.sign(&signer_pair.clone().into());
	let trusted_operation: TrustedOperation = signed_getter.clone().into();
	// encrypt call
	let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
	let mut encrypted_top: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
		.unwrap();

	// create trusted call signed
	let nonce = 0;
	let mrenclave = [0u8; 32];
	let call = TrustedCall::balance_set_balance(
		signer_pair.public().into(),
		signer_pair.public().into(),
		42,
		42,
	);
	let signed_call = call.sign(&signer_pair.into(), nonce, &mrenclave, &shard);
	let trusted_operation_call: TrustedOperation = signed_call.clone().into_trusted_operation(true);
	// encrypt call
	let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
	let mut encrypted_top_call: Vec<u8> = Vec::new();
	rsa_pubkey
		.encrypt_buffer(&trusted_operation_call.encode(), &mut encrypted_top_call)
		.unwrap();

	// when

	// submit top to pool
	let result = async { author.submit_top(encrypted_top.clone(), shard).await };
	executor::block_on(result).unwrap();

	let result = async { author.submit_top(encrypted_top_call.clone(), shard).await };
	executor::block_on(result).unwrap();

	// get pending extrinsics
	let (calls, getters) = author.get_pending_tops_separated(shard).unwrap();

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
	ensure_no_empty_shard_directory_exists();

	// create top pool
	unsafe { rpc::worker_api_direct::initialize_pool() };
	let shard = ShardIdentifier::default();
	// ensure state starts empty
	state::init_shard(&shard).unwrap();
	let mut state = Stf::init_state();
	assert_eq!(Stf::get_sidechain_block_number(&mut state).unwrap(), 0);

	// get index of current shard
	let index = get_current_shard_index(&shard);

	// Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let mut top_hash = H256::default();

	// load top pool
	{
		let pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
		let pool_guard = pool_mutex.lock().unwrap();
		let pool = Arc::new(pool_guard.deref());
		let author = Arc::new(Author::new(pool));

		// create trusted call signed
		let nonce = 0;
		let ocall_api = OCallComponentFactory::attestation_api();
		let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
		let signer_pair = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
		let call = TrustedCall::balance_transfer(
			signer_pair.public().into(),
			signer_pair.public().into(),
			42,
		);
		let signed_call = call.sign(&signer_pair.into(), nonce, &mrenclave, &shard);
		let trusted_operation: TrustedOperation = signed_call.into_trusted_operation(true);
		// encrypt call
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		let mut encrypted_top: Vec<u8> = Vec::new();
		rsa_pubkey
			.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
			.unwrap();

		// submit trusted call to top pool
		let result = async { author.submit_top(encrypted_top.clone(), shard).await };
		top_hash = executor::block_on(result).unwrap();
	}

	let rpc_ocall = Arc::new(EnclaveRpcOCallMock {});
	let on_chain_ocall = OCallComponentFactory::on_chain_api();

	// when
	let (confirm_calls, signed_blocks) = crate::execute_top_pool_calls(
		rpc_ocall.as_ref(),
		on_chain_ocall.as_ref(),
		latest_onchain_header,
	)
	.unwrap();

	debug!("got {} signed block(s)", signed_blocks.len());

	let signed_block = signed_blocks[index].clone();
	let mut opaque_call_vec = confirm_calls[index].0.clone();
	let xt_block_encoded = [SUBSTRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED].encode();
	let block_hash_encoded = blake2_256(&signed_block.block().encode()).encode();

	// then
	assert!(signed_block.verify_signature());
	assert_eq!(signed_block.block().block_number(), 1);
	assert_eq!(signed_block.block().signed_top_hashes()[0], top_hash);
	assert!(opaque_call_vec.starts_with(&xt_block_encoded));
	let mut stripped_opaque_call = opaque_call_vec.split_off(xt_block_encoded.len());
	assert!(stripped_opaque_call.starts_with(&shard.encode()));
	let stripped_opaque_call = stripped_opaque_call.split_off(shard.encode().len());
	assert!(stripped_opaque_call.starts_with(&block_hash_encoded));

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_create_state_diff() {
	// given
	ensure_no_empty_shard_directory_exists();

	// create top pool
	unsafe { rpc::worker_api_direct::initialize_pool() };
	let shard = ShardIdentifier::default();
	// Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let _rsa_pair = rsa3072::unseal_pair().unwrap();

	// ensure that state starts empty
	state::init_shard(&shard).unwrap();
	let state = Stf::init_state();

	// get index of current shard
	let index = get_current_shard_index(&shard);

	// create accounts
	let signer_without_money = Ed25519::unseal().unwrap();
	let pair_with_money = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
	let account_with_money = pair_with_money.public();
	let account_without_money = signer_without_money.public();
	let account_with_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_with_money.into());
	let account_without_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_without_money.into());

	let _prev_state_hash = state::write(state, &shard).unwrap();
	// load top pool
	{
		let pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
		let pool_guard = pool_mutex.lock().unwrap();
		let pool = Arc::new(pool_guard.deref());
		let author = Arc::new(Author::new(pool));

		// create trusted call signed
		let nonce = 0;
		let ocall_api = OCallComponentFactory::attestation_api();
		let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
		let call = TrustedCall::balance_transfer(
			account_with_money.into(),
			account_without_money.into(),
			1000,
		);
		let signed_call = call.sign(&pair_with_money.into(), nonce, &mrenclave, &shard);
		let trusted_operation: TrustedOperation = signed_call.into_trusted_operation(true);
		// encrypt call
		let mut encrypted_top: Vec<u8> = Vec::new();
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		rsa_pubkey
			.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
			.unwrap();

		// submit trusted call to top pool
		let result = async { author.submit_top(encrypted_top.clone(), shard).await };
		executor::block_on(result).unwrap();
	}

	let rpc_ocall = Arc::new(EnclaveRpcOCallMock {});
	let on_chain_ocall = OCallComponentFactory::on_chain_api();

	// when
	let (_, signed_blocks) = crate::execute_top_pool_calls(
		rpc_ocall.as_ref(),
		on_chain_ocall.as_ref(),
		latest_onchain_header,
	)
	.unwrap();
	let mut encrypted_payload: Vec<u8> = signed_blocks[index].block().state_payload().to_vec();
	aes::de_or_encrypt(&mut encrypted_payload).unwrap();
	let state_payload = StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap();
	let state_diff = StfStateTypeDiff::decode(state_payload.state_update().to_vec());

	// then
	let acc_info_vec = state_diff.get(&account_with_money_key_hash).unwrap().as_ref().unwrap();
	let new_balance_acc_with_money =
		AccountInfo::decode(&mut acc_info_vec.as_slice()).unwrap().data.free;
	let acc_info_vec = state_diff.get(&account_without_money_key_hash).unwrap().as_ref().unwrap();
	let new_balance_acc_wo_money =
		AccountInfo::decode(&mut acc_info_vec.as_slice()).unwrap().data.free;
	// get block number
	let block_number_key = storage_value_key("System", "Number");
	let new_block_number_encoded = state_diff.get(&block_number_key).unwrap().as_ref().unwrap();
	let new_block_number =
		substratee_worker_primitives::BlockNumber::decode(&mut new_block_number_encoded.as_slice())
			.unwrap();
	assert_eq!(state_diff.len(), 3);
	assert_eq!(new_balance_acc_wo_money, 1000);
	assert_eq!(new_balance_acc_with_money, 1000);
	assert_eq!(new_block_number, 1);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_executing_call_updates_account_nonce() {
	// given

	ensure_no_empty_shard_directory_exists();

	// create top pool
	unsafe { rpc::worker_api_direct::initialize_pool() };
	let shard = ShardIdentifier::default();
	// Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let _rsa_pair = rsa3072::unseal_pair().unwrap();

	// ensure that state starts empty
	state::init_shard(&shard).unwrap();
	let mut state = Stf::init_state();

	// create accounts
	let signer_without_money = Ed25519::unseal().unwrap();
	let pair_with_money = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
	let account_with_money = pair_with_money.public();
	let account_without_money = signer_without_money.public();
	let account_with_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_with_money.into());
	let account_without_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_without_money.into());

	let _prev_state_hash = state::write(state, &shard).unwrap();
	// load top pool
	{
		let pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
		let pool_guard = pool_mutex.lock().unwrap();
		let pool = Arc::new(pool_guard.deref());
		let author = Arc::new(Author::new(pool.clone()));

		// create trusted call signed
		let nonce = 0;
		let ocall_api = OCallComponentFactory::attestation_api();
		let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
		let call = TrustedCall::balance_transfer(
			account_with_money.into(),
			account_without_money.into(),
			1000,
		);
		let signed_call = call.sign(&pair_with_money.into(), nonce, &mrenclave, &shard);
		let trusted_operation: TrustedOperation = signed_call.into_trusted_operation(true);
		// encrypt call
		let mut encrypted_top: Vec<u8> = Vec::new();
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		rsa_pubkey
			.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
			.unwrap();

		// submit trusted call to top pool
		let result = async { author.submit_top(encrypted_top.clone(), shard).await };
		executor::block_on(result).unwrap();
	}

	let rpc_ocall = Arc::new(EnclaveRpcOCallMock {});
	let on_chain_ocall = OCallComponentFactory::on_chain_api();

	// when
	let (_, signed_blocks) = crate::execute_top_pool_calls(
		rpc_ocall.as_ref(),
		on_chain_ocall.as_ref(),
		latest_onchain_header,
	)
	.unwrap();

	// then
	let mut state = state::load(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut state, &account_with_money.into());
	assert_eq!(nonce, 1);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_invalid_nonce_call_is_not_executed() {
	// given

	ensure_no_empty_shard_directory_exists();

	// create top pool
	unsafe { rpc::worker_api_direct::initialize_pool() };
	let shard = ShardIdentifier::default();
	// Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let _rsa_pair = rsa3072::unseal_pair().unwrap();

	// ensure that state starts empty
	state::init_shard(&shard).unwrap();
	let mut state = Stf::init_state();

	// create accounts
	let signer_without_money = Ed25519::unseal().unwrap();
	let pair_with_money = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
	let account_with_money = pair_with_money.public();
	let account_without_money = signer_without_money.public();
	let account_with_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_with_money.into());
	let account_without_money_key_hash =
		substratee_stf::stf_sgx_primitives::account_key_hash(&account_without_money.into());

	let _prev_state_hash = state::write(state, &shard).unwrap();
	// load top pool
	{
		let pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
		let pool_guard = pool_mutex.lock().unwrap();
		let pool = Arc::new(pool_guard.deref());
		let author = Arc::new(Author::new(pool.clone()));

		// create trusted call signed
		let nonce = 10;
		let ocall_api = OCallComponentFactory::attestation_api();
		let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
		let call = TrustedCall::balance_transfer(
			account_with_money.into(),
			account_without_money.into(),
			1000,
		);
		let signed_call = call.sign(&pair_with_money.into(), nonce, &mrenclave, &shard);
		let trusted_operation: TrustedOperation = signed_call.into_trusted_operation(true);
		// encrypt call
		let mut encrypted_top: Vec<u8> = Vec::new();
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		rsa_pubkey
			.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
			.unwrap();

		// submit trusted call to top pool
		let result = async { author.submit_top(encrypted_top.clone(), shard).await };
		executor::block_on(result).unwrap();
	}

	let rpc_ocall = Arc::new(EnclaveRpcOCallMock {});
	let on_chain_ocall = OCallComponentFactory::on_chain_api();

	// when
	let (_, signed_blocks) = crate::execute_top_pool_calls(
		rpc_ocall.as_ref(),
		on_chain_ocall.as_ref(),
		latest_onchain_header,
	)
	.unwrap();

	// then
	let mut updated_state = state::load(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut updated_state, &account_with_money.into());
	assert_eq!(nonce, 0);

	let acc_data_with_money =
		Stf::account_data(&mut updated_state, &account_with_money.into()).unwrap();
	assert_eq!(acc_data_with_money.free, 2000);

	// clean up
	state::tests::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_non_root_shielding_call_is_not_executed() {
	// given
	ensure_no_empty_shard_directory_exists();

	// create top pool
	unsafe { rpc::worker_api_direct::initialize_pool() };
	let shard = ShardIdentifier::default();
	// Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
	let latest_onchain_header =
		Header::new(1, Default::default(), Default::default(), [69; 32].into(), Default::default());
	let _rsa_pair = rsa3072::unseal_pair().unwrap();

	// ensure that state starts empty
	state::init_shard(&shard).unwrap();
	let mut state = Stf::init_state();

	// create account
	let signer_pair = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
	let account = signer_pair.public();
	let prev_acc_money = Stf::account_data(&mut state, &account.into()).unwrap().free;
	// load top pool
	{
		let pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
		let pool_guard = pool_mutex.lock().unwrap();
		let pool = Arc::new(pool_guard.deref());
		let author = Arc::new(Author::new(pool.clone()));

		// create trusted call signed
		let nonce = 0;
		let ocall_api = OCallComponentFactory::attestation_api();
		let mrenclave = ocall_api.get_mrenclave_of_self().unwrap().m;
		let call = TrustedCall::balance_shield(account.into(), account.into(), 1000);
		let signed_call = call.sign(&signer_pair.into(), nonce, &mrenclave, &shard);
		let trusted_operation: TrustedOperation = signed_call.into_trusted_operation(true);
		// encrypt call
		let mut encrypted_top: Vec<u8> = Vec::new();
		let rsa_pubkey = rsa3072::unseal_pubkey().unwrap();
		rsa_pubkey
			.encrypt_buffer(&trusted_operation.encode(), &mut encrypted_top)
			.unwrap();

		// submit trusted call to top pool
		let result = async { author.submit_top(encrypted_top.clone(), shard).await };
		executor::block_on(result).unwrap();
	}

	let rpc_ocall = Arc::new(EnclaveRpcOCallMock {});
	let on_chain_ocall = OCallComponentFactory::on_chain_api();

	// when
	let (_, signed_blocks) = crate::execute_top_pool_calls(
		rpc_ocall.as_ref(),
		on_chain_ocall.as_ref(),
		latest_onchain_header,
	)
	.unwrap();

	// then
	let mut updated_state = state::load(&shard).unwrap();
	let nonce = Stf::account_nonce(&mut updated_state, &account.into());
	let new_acc_money = Stf::account_data(&mut updated_state, &account.into()).unwrap().free;
	assert_eq!(nonce, 0);
	assert_eq!(new_acc_money, prev_acc_money);

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
