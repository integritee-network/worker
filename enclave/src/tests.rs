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

use crate::aes;
use crate::attestation;
use crate::ed25519;
use crate::rpc;
use crate::rsa3072;
use crate::state;
use crate::top_pool;

use crate::{Timeout, WorkerRequest, WorkerResponse};
use log::*;

use sgx_tunittest::*;
use sgx_types::{sgx_status_t, size_t};

use substrate_api_client::utils::storage_key;
use substratee_worker_primitives::block::StatePayload;

use codec::{Decode, Encode};
use sp_core::{crypto::Pair, hashing::blake2_256, H256};

use crate::constants::{BLOCK_CONFIRMED, GETTERTIMEOUT, SUBSRATEE_REGISTRY_MODULE};

use std::string::String;
use std::vec::Vec;

use crate::ipfs::IpfsContent;
use core::ops::Deref;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::untrusted::time::SystemTimeEx;

use chain_relay::{Block, Header};
use sp_runtime::traits::Header as HeaderT;

use sgx_externalities::SgxExternalitiesTypeTrait;
use substratee_stf::StateTypeDiff as StfStateTypeDiff;
use substratee_stf::{ShardIdentifier, Stf, TrustedCall};

use jsonrpc_core::futures::executor;
use sp_core::ed25519 as spEd25519;
use substratee_stf::{TrustedGetter, TrustedOperation};

use rpc::author::{Author, AuthorApi};
use rpc::{api::FillerChainApi, basic_pool::BasicPool};

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
    rsgx_unit_tests!(
        top_pool::base_pool::test_should_import_transaction_to_ready,
        top_pool::base_pool::test_should_not_import_same_transaction_twice,
        top_pool::base_pool::test_should_import_transaction_to_future_and_promote_it_later,
        top_pool::base_pool::test_should_promote_a_subgraph,
        top_pool::base_pool::test_should_handle_a_cycle,
        top_pool::base_pool::test_can_track_heap_size,
        top_pool::base_pool::test_should_handle_a_cycle_with_low_priority,
        top_pool::base_pool::test_should_remove_invalid_transactions,
        top_pool::base_pool::test_should_prune_ready_transactions,
        top_pool::base_pool::test_transaction_debug,
        top_pool::base_pool::test_transaction_propagation,
        top_pool::base_pool::test_should_reject_future_transactions,
        top_pool::base_pool::test_should_clear_future_queue,
        top_pool::base_pool::test_should_accept_future_transactions_when_explicitly_asked_to,
        top_pool::primitives::test_h256,
        top_pool::pool::test_should_validate_and_import_transaction,
        top_pool::pool::test_should_reject_if_temporarily_banned,
        top_pool::pool::test_should_notify_about_pool_events,
        top_pool::pool::test_should_clear_stale_transactions,
        top_pool::pool::test_should_ban_mined_transactions,
        top_pool::pool::test_should_limit_futures,
        top_pool::pool::test_should_error_if_reject_immediately,
        top_pool::pool::test_should_reject_transactions_with_no_provides,
        top_pool::rotator::tests::test_should_not_ban_if_not_stale,
        top_pool::rotator::tests::test_should_ban_stale_extrinsic,
        top_pool::rotator::tests::test_should_clear_banned,
        top_pool::rotator::tests::test_should_garbage_collect,
        state::test_write_and_load_state_works,
        state::test_sgx_state_decode_encode_works,
        state::test_encrypt_decrypt_state_type_works,
        test_time_is_overdue,
        test_time_is_not_overdue,
        test_compose_block_and_confirmation,
        // these unit tests need an ipfs node running..
        // hence not really unit tests..?
        //ipfs::test_creates_ipfs_content_struct_works,
        //ipfs::test_verification_ok_for_correct_content,
        //ipfs::test_verification_fails_for_incorrect_content,
        //test_ocall_read_write_ipfs,
        test_ocall_worker_request,
        test_submit_trusted_call_to_top_pool,
        test_submit_trusted_getter_to_top_pool,
        test_differentiate_getter_and_call_works,
        test_create_block_and_confirmation_works,
        test_create_state_diff,
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
fn test_ocall_read_write_ipfs() {
    info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut cid_buf: Vec<u8> = vec![0; 46];
    let enc_state: Vec<u8> = vec![20; 4 * 512 * 1024];

    let _res = unsafe {
        crate::ocall_write_ipfs(
            &mut rt as *mut sgx_status_t,
            enc_state.as_ptr(),
            enc_state.len() as u32,
            cid_buf.as_mut_ptr(),
            cid_buf.len() as u32,
        )
    };

    let res = unsafe {
        crate::ocall_read_ipfs(
            &mut rt as *mut sgx_status_t,
            cid_buf.as_ptr(),
            cid_buf.len() as u32,
        )
    };

    if res == sgx_status_t::SGX_SUCCESS {
        let cid = std::str::from_utf8(&cid_buf).unwrap();
        let mut f = File::open(&cid).unwrap();
        let mut content_buf = Vec::new();
        f.read_to_end(&mut content_buf).unwrap();
        info!("reading file {:?} of size {} bytes", f, &content_buf.len());

        let mut ipfs_content = IpfsContent::new(cid, content_buf);
        let verification = ipfs_content.verify();
        assert_eq!(verification.is_ok(), true);
    } else {
        error!("was not able to write to file");
        assert!(false);
    }
}

#[allow(unused)]
fn test_ocall_worker_request() {
    info!("testing ocall_worker_request. Hopefully substraTEE-node is running...");
    let mut requests = Vec::new();

    requests.push(WorkerRequest::ChainStorage(
        storage_key("Balances", "TotalIssuance").0,
        None,
    ));

    let mut resp: Vec<WorkerResponse<Vec<u8>>> = match crate::worker_request(requests) {
        Ok(response) => response,
        Err(e) => panic!("Worker response decode failed. Error: {:?}", e),
    };

    let first = resp.pop().unwrap();
    info!("Worker response: {:?}", first);

    let (total_issuance, proof) = match first {
        WorkerResponse::ChainStorage(_storage_key, value, proof) => (value, proof),
    };

    info!("Total Issuance is: {:?}", total_issuance);
    info!("Proof: {:?}", proof)
}

#[allow(unused)]
fn test_time_is_overdue() {
    // given
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // when
    let before_start_time = (start_time * 1000 - GETTERTIMEOUT) / 1000;
    let time_has_run_out = crate::time_is_overdue(Timeout::Getter, before_start_time);
    // then
    assert!(time_has_run_out)
}

#[allow(unused)]
fn test_time_is_not_overdue() {
    // given
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // when
    let time_has_run_out = crate::time_is_overdue(Timeout::Call, start_time);
    // then
    assert!(!time_has_run_out)
}

#[allow(unused)]
fn test_compose_block_and_confirmation() {
    // given
    let latest_onchain_header = Header::new(
        1,
        Default::default(),
        Default::default(),
        [69; 32].into(),
        Default::default(),
    );
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
    let xt_block_encoded = [SUBSRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED].encode();
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
}

#[allow(unused)]
fn test_submit_trusted_call_to_top_pool() {
    // given

    // create top pool
    let api: Arc<FillerChainApi<Block>> = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(Default::default(), api);
    let author = Author::new(Arc::new(&tx_pool));

    // create trusted call signed
    let nonce = 1;
    let mrenclave = [0u8; 32];
    let shard = ShardIdentifier::default();
    // ensure state starts empty
    state::init_shard(&shard).unwrap();
    Stf::init_state();
    let signer_pair = ed25519::unseal_pair().unwrap();
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
}

#[allow(unused)]
fn test_submit_trusted_getter_to_top_pool() {
    // given

    // create top pool
    let api: Arc<FillerChainApi<Block>> = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(Default::default(), api);
    let author = Author::new(Arc::new(&tx_pool));

    // create trusted getter signed
    let shard = ShardIdentifier::default();
    // ensure state starts empty
    state::init_shard(&shard).unwrap();
    Stf::init_state();
    let signer_pair = ed25519::unseal_pair().unwrap();
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
}

#[allow(unused)]
fn test_differentiate_getter_and_call_works() {
    // given

    // create top pool
    let api: Arc<FillerChainApi<Block>> = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(Default::default(), api);
    let author = Author::new(Arc::new(&tx_pool));
    // create trusted getter signed
    let shard = ShardIdentifier::default();
    // ensure state starts empty
    state::init_shard(&shard).unwrap();
    Stf::init_state();

    let signer_pair = ed25519::unseal_pair().unwrap();
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
    let nonce = 1;
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
    // Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
    let latest_onchain_header = Header::new(
        1,
        Default::default(),
        Default::default(),
        [69; 32].into(),
        Default::default(),
    );
    let mut top_hash = H256::default();

    // load top pool
    {
        let &ref pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
        let pool_guard = pool_mutex.lock().unwrap();
        let pool = Arc::new(pool_guard.deref());
        let author = Arc::new(Author::new(pool));

        // create trusted call signed
        let nonce = 1;
        //let mrenclave = [0u8; 32];
        let mrenclave = attestation::get_mrenclave_of_self().unwrap().m;
        let signer_pair = ed25519::unseal_pair().unwrap();
        let call = TrustedCall::balance_transfer(
            signer_pair.public().into(),
            signer_pair.public().into(),
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

        // submit trusted call to top pool
        let result = async { author.submit_top(encrypted_top.clone(), shard).await };
        top_hash = executor::block_on(result).unwrap();
    }

    // when
    let (confirm_calls, signed_blocks) =
        crate::execute_top_pool_calls(latest_onchain_header).unwrap();

    let signed_block = signed_blocks[0].clone();
    let mut opaque_call_vec = confirm_calls[0].0.clone();
    let xt_block_encoded = [SUBSRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED].encode();
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
    state::remove_shard_dir(&shard);
}

#[allow(unused)]
fn test_create_state_diff() {
    // given

    ensure_no_empty_shard_directory_exists();

    // create top pool
    unsafe { rpc::worker_api_direct::initialize_pool() };
    let shard = ShardIdentifier::default();
    // Header::new(Number, extrinsicroot, stateroot, parenthash, digest)
    let latest_onchain_header = Header::new(
        1,
        Default::default(),
        Default::default(),
        [69; 32].into(),
        Default::default(),
    );
    let _rsa_pair = rsa3072::unseal_pair().unwrap();

    // ensure that state starts empty
    state::init_shard(&shard).unwrap();
    let state = Stf::init_state();

    // create accounts
    let signer_without_money = ed25519::unseal_pair().unwrap();
    let pair_with_money = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
    let account_with_money = pair_with_money.public();
    let account_without_money = signer_without_money.public();
    let account_with_money_key_hash =
        substratee_stf::sgx::nonce_key_hash(&account_with_money.into());
    let account_without_money_key_hash =
        substratee_stf::sgx::nonce_key_hash(&account_without_money.into());

    let _prev_state_hash = state::write(state.clone(), &shard).unwrap();
    // load top pool
    {
        let &ref pool_mutex = rpc::worker_api_direct::load_top_pool().unwrap();
        let pool_guard = pool_mutex.lock().unwrap();
        let pool = Arc::new(pool_guard.deref());
        let author = Arc::new(Author::new(pool));

        // create trusted call signed
        let nonce = 1;
        let mrenclave = attestation::get_mrenclave_of_self().unwrap().m;
        let call = TrustedCall::balance_transfer(
            account_with_money.into(),
            account_without_money.into(),
            1000,
        );
        let signed_call = call.sign(&pair_with_money.into(), nonce, &mrenclave, &shard);
        let trusted_operation: TrustedOperation = signed_call.clone().into_trusted_operation(true);
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

    // when
    let (_, signed_blocks) = crate::execute_top_pool_calls(latest_onchain_header).unwrap();
    let mut encrypted_payload: Vec<u8> = signed_blocks[0].block().state_payload().to_vec();
    aes::de_or_encrypt(&mut encrypted_payload).unwrap();
    let state_payload = StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap();
    let state_diff = StfStateTypeDiff::decode(state_payload.state_update().to_vec());

    // then
    let acc_info_vec = state_diff
        .get(&account_with_money_key_hash)
        .unwrap()
        .as_ref()
        .unwrap();
    let new_balance_acc_with_money =
        substratee_stf::sgx::AccountInfo::decode(&mut acc_info_vec.as_slice())
            .unwrap()
            .data
            .free;
    let acc_info_vec = state_diff
        .get(&account_without_money_key_hash)
        .unwrap()
        .as_ref()
        .unwrap();
    let new_balance_acc_wo_money =
        substratee_stf::sgx::AccountInfo::decode(&mut acc_info_vec.as_slice())
            .unwrap()
            .data
            .free;
    // get block number
    let block_number_key = substratee_stf::sgx::storage_value_key("System", "Number");
    let new_block_number_encoded = state_diff.get(&block_number_key).unwrap().as_ref().unwrap();
    let new_block_number =
        substratee_worker_primitives::BlockNumber::decode(&mut new_block_number_encoded.as_slice())
            .unwrap();
    assert_eq!(state_diff.len(), 3);
    assert_eq!(new_balance_acc_wo_money, 1000);
    assert_eq!(new_balance_acc_with_money, 1000);
    assert_eq!(new_block_number, 1);

    // clean up
    state::remove_shard_dir(&shard);
}