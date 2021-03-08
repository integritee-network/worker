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
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![crate_name = "substratee_worker_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

use log::*;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use base58::ToBase58;

use sgx_tunittest::*;
use sgx_types::{sgx_epid_group_id_t, sgx_status_t, sgx_target_info_t, size_t, SgxResult};

use substrate_api_client::{compose_extrinsic_offline, utils::storage_key};
use substratee_node_primitives::ShieldFundsFn;
use substratee_worker_primitives::block::{
    Block as SidechainBlock, SignedBlock as SignedSidechainBlock, StatePayload,
};
use substratee_worker_primitives::BlockHash;

use codec::{Decode, Encode};
use sp_core::{crypto::Pair, hashing::blake2_256, H256};
use sp_finality_grandpa::VersionedAuthorityList;

use constants::{
    BLOCK_CONFIRMED, CALLTIMEOUT, CALL_CONFIRMED, GETTERTIMEOUT, RUNTIME_SPEC_VERSION,
    RUNTIME_TRANSACTION_VERSION, SUBSRATEE_REGISTRY_MODULE,
};

use std::slice;
use std::string::String;
use std::vec::Vec;

use core::ops::Deref;
use ipfs::IpfsContent;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::sync::{SgxMutex, SgxMutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use std::untrusted::time::SystemTimeEx;
use utils::write_slice_and_whitespace_pad;

use crate::constants::{CALL_WORKER, SHIELD_FUNDS};
use crate::utils::UnwrapOrSgxErrorUnexpected;
use chain_relay::{
    storage_proof::{StorageProof, StorageProofChecker},
    Block, Header, LightValidation,
};
use sp_runtime::OpaqueExtrinsic;
use sp_runtime::{generic::SignedBlock, traits::Header as HeaderT};
use substrate_api_client::extrinsic::xt_primitives::UncheckedExtrinsicV4;

use sgx_externalities::SgxExternalitiesTypeTrait;
use substratee_stf::sgx::{shards_key_hash, storage_hashes_to_update_per_shard, OpaqueCall};
use substratee_stf::{
    AccountId, Getter, ShardIdentifier, Stf, TrustedCall, TrustedCallSigned, TrustedGetterSigned,
};
use substratee_stf::{
    State as StfState, StateType as StfStateType, StateTypeDiff as StfStateTypeDiff,
};

use rpc::author::{hash::TrustedOperationOrHash, Author, AuthorApi};
use rpc::worker_api_direct;
use rpc::{api::FillerChainApi, basic_pool::BasicPool};

mod aes;
mod attestation;
mod constants;
mod ed25519;
mod io;
mod ipfs;
mod rsa3072;
mod state;
mod utils;

pub mod cert;
pub mod hex;
pub mod rpc;
pub mod tls_ra;
pub mod top_pool;

pub const CERTEXPIRYDAYS: i64 = 90i64;

#[derive(Debug, Clone, PartialEq)]
pub enum Timeout {
    Call,
    Getter,
}

pub type Hash = sp_core::H256;
type BPool = BasicPool<FillerChainApi<Block>, Block>;

#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
    // initialize the logging environment in the enclave
    env_logger::init();

    if let Err(status) = ed25519::create_sealed_if_absent() {
        return status;
    }

    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    info!(
        "[Enclave initialized] Ed25519 prim raw : {:?}",
        signer.public().0
    );

    if let Err(status) = rsa3072::create_sealed_if_absent() {
        return status;
    }

    // create the aes key that is used for state encryption such that a key is always present in tests.
    // It will be overwritten anyway if mutual remote attastation is performed with the primary worker
    if let Err(status) = aes::create_sealed_if_absent() {
        return status;
    }

    // for debug purposes, list shards. no problem to panic if fails
    let shards = state::list_shards().unwrap();
    debug!("found the following {} shards on disk:", shards.len());
    for s in shards {
        debug!("{}", s.encode().to_base58())
    }
    //shards.into_iter().map(|s| debug!("{}", s.encode().to_base58()));

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
    pubkey: *mut u8,
    pubkey_size: u32,
) -> sgx_status_t {
    let rsa_pubkey = match rsa3072::unseal_pubkey() {
        Ok(key) => key,
        Err(status) => return status,
    };

    let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
        Ok(k) => k,
        Err(x) => {
            println!(
                "[Enclave] can't serialize rsa_pubkey {:?} {}",
                rsa_pubkey, x
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
    write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
    if let Err(status) = ed25519::create_sealed_if_absent() {
        return status;
    }

    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    debug!("Restored ECC pubkey: {:?}", signer.public());

    let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
    pubkey_slice.clone_from_slice(&signer.public());

    sgx_status_t::SGX_SUCCESS
}

fn create_extrinsics(
    validator: LightValidation,
    calls_buffer: Vec<OpaqueCall>,
    mut nonce: u32,
) -> SgxResult<Vec<Vec<u8>>> {
    // get information for composing the extrinsic
    let signer = ed25519::unseal_pair()?;
    debug!("Restored ECC pubkey: {:?}", signer.public());

    let extrinsics_buffer: Vec<Vec<u8>> = calls_buffer
        .into_iter()
        .map(|call| {
            let xt = compose_extrinsic_offline!(
                signer.clone(),
                call,
                nonce,
                Era::Immortal,
                validator.genesis_hash(validator.num_relays).unwrap(),
                validator.genesis_hash(validator.num_relays).unwrap(),
                RUNTIME_SPEC_VERSION,
                RUNTIME_TRANSACTION_VERSION
            )
            .encode();
            nonce += 1;
            xt
        })
        .collect();

    Ok(extrinsics_buffer)
}

#[no_mangle]
pub unsafe extern "C" fn get_state(
    trusted_op: *const u8,
    trusted_op_size: u32,
    shard: *const u8,
    shard_size: u32,
    value: *mut u8,
    value_size: u32,
) -> sgx_status_t {
    let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
    let mut trusted_op_slice = slice::from_raw_parts(trusted_op, trusted_op_size as usize);
    let value_slice = slice::from_raw_parts_mut(value, value_size as usize);
    let getter = Getter::decode(&mut trusted_op_slice).unwrap();

    if let Getter::trusted(trusted_getter_signed) = getter.clone() {
        debug!("verifying signature of TrustedGetterSigned");
        if let false = trusted_getter_signed.verify_signature() {
            error!("bad signature");
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }

    if !state::exists(&shard) {
        info!("Initialized new shard that was queried chain: {:?}", shard);
        if let Err(e) = state::init_shard(&shard) {
            return e;
        }
    }

    let mut state = match state::load(&shard) {
        Ok(s) => s,
        Err(status) => return status,
    };

    let validator = match io::light_validation::unseal() {
        Ok(val) => val,
        Err(e) => return e,
    };

    let latest_header = validator
        .latest_finalized_header(validator.num_relays)
        .unwrap();

    // FIXME: not sure we will ever need this as we are querying trusted state, not onchain state
    // i.e. demurrage could be correctly applied with this, but the client could do that too.
    debug!("Update STF storage!");
    let requests: Vec<WorkerRequest> = Stf::get_storage_hashes_to_update_for_getter(&getter)
        .into_iter()
        .map(|key| WorkerRequest::ChainStorage(key, Some(latest_header.hash())))
        .collect();

    if !requests.is_empty() {
        let responses: Vec<WorkerResponse<Vec<u8>>> = match worker_request(requests) {
            Ok(resp) => resp,
            Err(e) => return e,
        };

        let update_map = match verify_worker_responses(responses, latest_header) {
            Ok(map) => map,
            Err(e) => return e,
        };

        Stf::update_storage(&mut state, &update_map);
    }

    debug!("calling into STF to get state");
    let value_opt = Stf::get_state(&mut state, getter);

    debug!("returning getter result");
    write_slice_and_whitespace_pad(value_slice, value_opt.encode());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_chain_relay(
    genesis_header: *const u8,
    genesis_header_size: usize,
    authority_list: *const u8,
    authority_list_size: usize,
    authority_proof: *const u8,
    authority_proof_size: usize,
    latest_header: *mut u8,
    latest_header_size: usize,
) -> sgx_status_t {
    info!("Initializing Chain Relay!");

    let mut header = slice::from_raw_parts(genesis_header, genesis_header_size);
    let latest_header_slice = slice::from_raw_parts_mut(latest_header, latest_header_size);
    let mut auth = slice::from_raw_parts(authority_list, authority_list_size);
    let mut proof = slice::from_raw_parts(authority_proof, authority_proof_size);

    let header = match Header::decode(&mut header) {
        Ok(h) => h,
        Err(e) => {
            error!("Decoding Header failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let auth = match VersionedAuthorityList::decode(&mut auth) {
        Ok(a) => a,
        Err(e) => {
            error!("Decoding VersionedAuthorityList failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let proof = match StorageProof::decode(&mut proof) {
        Ok(h) => h,
        Err(e) => {
            error!("Decoding Header failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    match io::light_validation::read_or_init_validator(header, auth, proof) {
        Ok(header) => write_slice_and_whitespace_pad(latest_header_slice, header.encode()),
        Err(e) => return e,
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn produce_blocks(
    blocks_to_sync: *const u8,
    blocks_to_sync_size: usize,
    nonce: *const u32,
) -> sgx_status_t {
    let mut blocks_to_sync_slice = slice::from_raw_parts(blocks_to_sync, blocks_to_sync_size);

    let blocks_to_sync: Vec<SignedBlock<Block>> = match Decode::decode(&mut blocks_to_sync_slice) {
        Ok(b) => b,
        Err(e) => {
            error!("Decoding signed blocks failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let mut validator = match io::light_validation::unseal() {
        Ok(v) => v,
        Err(e) => return e,
    };

    let mut calls = Vec::<OpaqueCall>::new();

    debug!("Syncing chain relay!");
    if !blocks_to_sync.is_empty() {
        for signed_block in blocks_to_sync.clone().into_iter() {
            validator
                .check_xt_inclusion(validator.num_relays, &signed_block.block)
                .unwrap(); // panic can only happen if relay_id does not exist
            if let Err(e) = validator.submit_simple_header(
                validator.num_relays,
                signed_block.block.header.clone(),
                signed_block.justification.clone(),
            ) {
                error!("Block verification failed. Error : {:?}", e);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }

            if update_states(signed_block.block.header.clone()).is_err() {
                error!("Error performing state updates upon block import");
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }

            // indirect worker calls not supported anymore since M8.2
            // might be used again in future versions
            /* match scan_block_for_relevant_xt(&signed_block.block) {
                Ok(c) => calls.extend(c.into_iter()),
                Err(_) => error!("Error executing relevant extrinsics"),
            }; */
        }
    }
    // get header of last block
    let latest_onchain_header: Header = validator
        .latest_finalized_header(validator.num_relays)
        .unwrap();
    // execute pending calls from operation pool and create block
    // (one per shard) as opaque call
    let signed_blocks: Vec<SignedSidechainBlock> =
        match execute_top_pool_calls(latest_onchain_header) {
            Ok((confirm_calls, signed_blocks)) => {
                calls.extend(confirm_calls.into_iter());
                signed_blocks
            }
            Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
        };

    let extrinsics = match create_extrinsics(validator.clone(), calls, *nonce) {
        Ok(xt) => xt,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    // store extrinsics in chain relay for finalization check
    for xt in extrinsics.iter() {
        validator
            .submit_xt_to_be_included(
                validator.num_relays,
                OpaqueExtrinsic::from_bytes(xt.as_slice()).unwrap(),
            )
            .unwrap();
    }

    if let Err(_) = io::light_validation::seal(validator) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    };

    // ocall to worker to store signed block and send block confirmation
    if let Err(_e) = send_block_and_confirmation(extrinsics, signed_blocks) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t::SGX_SUCCESS
}

fn send_block_and_confirmation(
    confirmations: Vec<Vec<u8>>,
    signed_blocks: Vec<SignedSidechainBlock>,
) -> SgxResult<()> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_send_block_and_confirmation(
            &mut rt as *mut sgx_status_t,
            confirmations.encode().as_ptr(),
            confirmations.encode().len() as u32,
            signed_blocks.encode().as_ptr(),
            signed_blocks.encode().len() as u32,
        )
    };

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    Ok(())
}

fn get_stf_state(
    trusted_getter_signed: TrustedGetterSigned,
    shard: ShardIdentifier,
) -> Option<Vec<u8>> {
    debug!("verifying signature of TrustedGetterSigned");
    if let false = trusted_getter_signed.verify_signature() {
        error!("bad signature");
        return None;
    }

    if !state::exists(&shard) {
        info!("Initialized new shard that was queried chain: {:?}", shard);
        if let Err(e) = state::init_shard(&shard) {
            error!("Error initialising shard {:?} state: Error: {:?}", shard, e);
            return None;
        }
    }

    let mut state = match state::load(&shard) {
        Ok(s) => s,
        Err(e) => {
            error!("Error loading shard {:?}: Error: {:?}", shard, e);
            return None;
        }
    };

    debug!("calling into STF to get state");
    Stf::get_state(&mut state, trusted_getter_signed.into())
}

fn execute_top_pool_calls(
    latest_onchain_header: Header,
) -> SgxResult<(Vec<OpaqueCall>, Vec<SignedSidechainBlock>)> {
    debug!("Executing pending pool operations");
    let mut calls = Vec::<OpaqueCall>::new();
    let mut blocks = Vec::<SignedSidechainBlock>::new();
    {
        // load top pool
        let &ref pool_mutex: &SgxMutex<BPool> = match rpc::worker_api_direct::load_top_pool() {
            Some(mutex) => mutex,
            None => {
                error!("Could not get mutex to pool");
                return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
            }
        };
        let pool_guard: SgxMutexGuard<BPool> = pool_mutex.lock().unwrap();
        let pool: Arc<&BPool> = Arc::new(pool_guard.deref());
        let author: Arc<Author<&BPool>> = Arc::new(Author::new(pool.clone()));

        // get all shards
        let shards = state::list_shards()?;

        // Handle trusted getters
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut is_done = false;
        for shard in shards.clone().into_iter() {
            // retrieve trusted operations from pool
            let trusted_getters = match author.get_pending_tops_separated(shard) {
                Ok((_, getters)) => getters,
                Err(_) => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
            };
            for trusted_getter_signed in trusted_getters.into_iter() {
                // get state
                let value_opt = get_stf_state(trusted_getter_signed.clone(), shard);
                // get hash
                let hash_of_getter = author.hash_of(&trusted_getter_signed.into());
                // let client know of current state
                if let Err(_) = worker_api_direct::send_state(hash_of_getter, value_opt) {
                    error!("Could not get state from stf");
                }
                // remove getter from pool
                if let Err(e) = author.remove_top(
                    vec![TrustedOperationOrHash::Hash(hash_of_getter)],
                    shard,
                    false,
                ) {
                    error!(
                        "Error removing trusted operation from top pool: Error: {:?}",
                        e
                    );
                }
                // Check time
                if time_is_overdue(Timeout::Getter, start_time) {
                    is_done = true;
                    break;
                }
            }
            if is_done {
                break;
            }
        }

        // Handle trusted calls
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let mut is_done = false;
        for shard in shards.into_iter() {
            let mut call_hashes = Vec::<H256>::new();

            // load state before executing any calls
            let mut state = if state::exists(&shard) {
                state::load(&shard)?
            } else {
                state::init_shard(&shard)?;
                Stf::init_state()
            };
            // save the state hash before call executions
            // (needed for block composition)
            let prev_state_hash = state::hash_of(state.state.clone())?;

            // retrieve trusted operations from pool
            let trusted_calls = match author.get_pending_tops_separated(shard) {
                Ok((calls, _)) => calls,
                Err(_) => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
            };
            // call execution
            for trusted_call_signed in trusted_calls.into_iter() {
                match handle_trusted_worker_call(
                    &mut calls,
                    &mut state,
                    trusted_call_signed,
                    latest_onchain_header.clone(),
                    shard,
                    Some(author.clone()),
                ) {
                    Ok(hash) => {
                        if let Some(hash) = hash {
                            call_hashes.push(hash)
                        }
                    }
                    Err(e) => error!("Error performing worker call: Error: {:?}", e),
                };
                // Check time
                if time_is_overdue(Timeout::Call, start_time) {
                    is_done = true;
                    break;
                }
            }
            // create new block
            match compose_block_and_confirmation(
                latest_onchain_header.clone(),
                call_hashes,
                shard,
                prev_state_hash,
                &mut state,
            ) {
                Ok((block_confirm, signed_block)) => {
                    calls.push(block_confirm);
                    blocks.push(signed_block.clone());

                    // Notify watching clients of InSidechainBlock
                    let composed_block = signed_block.block();
                    let block_hash: BlockHash = blake2_256(&composed_block.encode()).into();
                    pool.pool()
                        .validated_pool()
                        .on_block_created(composed_block.signed_top_hashes(), block_hash);
                }
                Err(e) => error!("Could not compose block confirmation: {:?}", e),
            }
            // save updated state after call executions
            let _new_state_hash = state::write(state.clone(), &shard)?;

            if is_done {
                break;
            }
        }
    }

    Ok((calls, blocks))
}

/// Checks if the time of call execution or getter is overdue
/// Returns true if specified time is exceeded
pub fn time_is_overdue(timeout: Timeout, start_time: i64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let max_time_ms: i64 = match timeout {
        Timeout::Call => CALLTIMEOUT,
        Timeout::Getter => GETTERTIMEOUT,
    };
    if (now - start_time) * 1000 >= max_time_ms {
        true
    } else {
        false
    }
}

/// Composes a sidechain block of a shard
pub fn compose_block_and_confirmation(
    latest_onchain_header: Header,
    top_call_hashes: Vec<H256>,
    shard: ShardIdentifier,
    state_hash_apriori: H256,
    state: &mut StfState,
) -> SgxResult<(OpaqueCall, SignedSidechainBlock)> {
    let signer_pair = ed25519::unseal_pair()?;
    let layer_one_head = latest_onchain_header.hash();

    let block_number = match Stf::get_block_number(state) {
        Some(number) => number + 1,
        None => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    };
    Stf::update_block_number(state, block_number.into());

    let block_number: u64 = (block_number).into(); //FIXME! Should be either u64 or u32! Not both..
    let parent_hash = match Stf::get_last_block_hash(state) {
        Some(hash) => hash,
        None => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    };
    // hash previous of state
    let state_hash_aposteriori = state::hash_of(state.state.clone())?;
    let state_update = state.state_diff.clone().encode();

    // create encrypted payload
    let mut payload: Vec<u8> =
        StatePayload::new(state_hash_apriori, state_hash_aposteriori, state_update).encode();
    aes::de_or_encrypt(&mut payload)?;

    let block = SidechainBlock::construct_block(
        signer_pair.public().into(),
        block_number,
        parent_hash,
        layer_one_head,
        shard,
        top_call_hashes,
        payload,
    );

    let signed_block = block.sign(&signer_pair);

    let block_hash = blake2_256(&block.encode());
    debug!("Block hash 0x{}", hex::encode_hex(&block_hash));
    Stf::update_last_block_hash(state, block_hash.into());

    let xt_block = [SUBSRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED];
    let opaque_call =
        OpaqueCall((xt_block, shard, block_hash, state_hash_aposteriori.encode()).encode());
    Ok((opaque_call, signed_block))
}

pub fn update_states(header: Header) -> SgxResult<()> {
    debug!("Update STF storage upon block import!");
    let requests: Vec<WorkerRequest> = Stf::storage_hashes_to_update_on_block()
        .into_iter()
        .map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
        .collect();

    if requests.is_empty() {
        return Ok(());
    }

    // global requests they are the same for every shard
    let responses: Vec<WorkerResponse<Vec<u8>>> = worker_request(requests)?;
    let update_map = verify_worker_responses(responses, header.clone())?;
    // look for new shards an initialize them
    if let Some(maybe_shards) = update_map.get(&shards_key_hash()) {
        match maybe_shards {
            Some(shards) => {
                let shards: Vec<ShardIdentifier> = Decode::decode(&mut shards.as_slice())
                    .sgx_error_with_log("error decoding shards")?;

                for s in shards {
                    if !state::exists(&s) {
                        info!("Initialized new shard that was found on chain: {:?}", s);
                        state::init_shard(&s)?;
                    }
                    // per shard (cid) requests
                    let per_shard_request = storage_hashes_to_update_per_shard(&s)
                        .into_iter()
                        .map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
                        .collect();

                    let responses: Vec<WorkerResponse<Vec<u8>>> =
                        worker_request(per_shard_request)?;
                    let per_shard_update_map = verify_worker_responses(responses, header.clone())?;

                    let mut state = state::load(&s)?;
                    Stf::update_storage(&mut state, &per_shard_update_map);
                    Stf::update_storage(&mut state, &update_map);

                    // block number is purged from the substrate state so it can't be read like other storage values
                    // TODO: does this stay like this? (=block number sidechain equals block number of main chain?)
                    // TODO: Parent hash update here aswell?
                    // Stf::update_block_number(&mut state, header.number);

                    state::write(state, &s)?;
                }
            }
            None => info!("No shards are on the chain yet"),
        };
    };
    Ok(())
}

/// Scans blocks for extrinsics that ask the enclave to execute some actions.
pub fn scan_block_for_relevant_xt(block: &Block) -> SgxResult<Vec<OpaqueCall>> {
    debug!("Scanning block {} for relevant xt", block.header.number());
    let mut calls = Vec::<OpaqueCall>::new();
    for xt_opaque in block.extrinsics.iter() {
        if let Ok(xt) =
            UncheckedExtrinsicV4::<ShieldFundsFn>::decode(&mut xt_opaque.encode().as_slice())
        {
            // confirm call decodes successfully as well
            if xt.function.0 == [SUBSRATEE_REGISTRY_MODULE, SHIELD_FUNDS] {
                if let Err(e) = handle_shield_funds_xt(&mut calls, xt) {
                    error!("Error performing shieldfunds. Error: {:?}", e);
                }
            }
        };

        /* if let Ok(xt) =
            UncheckedExtrinsicV4::<CallWorkerFn>::decode(&mut xt_opaque.encode().as_slice())
        {
            if xt.function.0 == [SUBSRATEE_REGISTRY_MODULE, CALL_WORKER] {
                if let Ok((decrypted_trusted_call, shard)) = decrypt_unchecked_extrinsic(xt) {
                    if let Err(e) = handle_trusted_worker_call(
                        &mut calls,
                        decrypted_trusted_call,
                        block.header.clone(),
                        shard,
                        None,
                    ) {
                        error!("Error performing worker call: Error: {:?}", e);
                    }
                }
            }
        } */
    }
    Ok(calls)
}

fn handle_shield_funds_xt(
    calls: &mut Vec<OpaqueCall>,
    xt: UncheckedExtrinsicV4<ShieldFundsFn>,
) -> SgxResult<()> {
    let (call, account_encrypted, amount, shard) = xt.function.clone();
    info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        call, account_encrypted, amount, shard.encode().to_base58(),
    );

    let mut state = if state::exists(&shard) {
        state::load(&shard)?
    } else {
        state::init_shard(&shard)?;
        Stf::init_state()
    };

    debug!("decrypt the call");
    let rsa_keypair = rsa3072::unseal_pair()?;
    let account_vec = rsa3072::decrypt(&account_encrypted, &rsa_keypair)?;
    let account = AccountId::decode(&mut account_vec.as_slice())
        .sgx_error_with_log("[ShieldFunds] Could not decode account")?;

    if let Err(e) = Stf::execute(
        &mut state,
        TrustedCallSigned::new(
            TrustedCall::balance_shield(account, amount),
            0,                  //nonce
            Default::default(), //don't care about signature here
        ),
        calls,
    ) {
        error!("Error performing Stf::execute. Error: {:?}", e);
        return Ok(());
    }

    let state_hash = state::write(state, &shard)?;

    let xt_call = [SUBSRATEE_REGISTRY_MODULE, CALL_CONFIRMED];
    let call_hash = blake2_256(&xt.encode());
    debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

    calls.push(OpaqueCall(
        (xt_call, shard, call_hash, state_hash.encode()).encode(),
    ));

    Ok(())
}

/* fn decrypt_unchecked_extrinsic(
    xt: UncheckedExtrinsicV4<CallWorkerFn>,
) -> SgxResult<(TrustedCallSigned, ShardIdentifier)> {
    let (call, request) = xt.function;
    let (shard, cyphertext) = (request.shard, request.cyphertext);
    debug!("Found CallWorker extrinsic in block: \nCall: {:?} \nRequest: \nshard: {}\ncyphertext: {:?}",
        call,
        shard.encode().to_base58(),
        cyphertext
    );

    debug!("decrypt the call");
    let rsa_keypair = rsa3072::unseal_pair()?;
    let request_vec = rsa3072::decrypt(&cyphertext, &rsa_keypair)?;
    match TrustedCallSigned::decode(&mut request_vec.as_slice()) {
        Ok(call) => Ok((call, shard)),
        Err(_) => Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
    }
}
 */
fn handle_trusted_worker_call(
    calls: &mut Vec<OpaqueCall>,
    state: &mut StfState,
    stf_call_signed: TrustedCallSigned,
    header: Header,
    shard: ShardIdentifier,
    author_pointer: Option<Arc<Author<&BPool>>>,
) -> SgxResult<Option<H256>> {
    debug!("query mrenclave of self");
    let mrenclave = attestation::get_mrenclave_of_self()?;

    debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());
    if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
        error!("TrustedCallSigned: bad signature");
        // do not panic here or users will be able to shoot workers dead by supplying a bad signature
        if let Some(author) = author_pointer {
            // remove call as invalid from pool
            let inblock = false;
            author
                .remove_top(
                    vec![TrustedOperationOrHash::Operation(
                        stf_call_signed.into_trusted_operation(true),
                    )],
                    shard,
                    inblock,
                )
                .unwrap();
        }
        return Ok(None);
    }

    // Necessary because chain relay sync may not be up to date
    // see issue #208
    debug!("Update STF storage!");
    let requests = Stf::get_storage_hashes_to_update(&stf_call_signed)
        .into_iter()
        .map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
        .collect();

    let responses: Vec<WorkerResponse<Vec<u8>>> = worker_request(requests)?;

    let update_map = verify_worker_responses(responses, header)?;

    Stf::update_storage(state, &update_map);

    debug!("execute STF");
    if let Err(e) = Stf::execute(state, stf_call_signed.clone(), calls) {
        if let Some(author) = author_pointer {
            // remove call as invalid from pool
            let inblock = false;
            author
                .remove_top(
                    vec![TrustedOperationOrHash::Operation(
                        stf_call_signed.into_trusted_operation(true),
                    )],
                    shard,
                    inblock,
                )
                .unwrap();
        }
        error!("Error performing Stf::execute. Error: {:?}", e);

        return Ok(None);
    }

    if let Some(author) = author_pointer {
        // TODO: prune instead of remove_top ? Block needs to be known
        // remove call from pool as valid
        // TODO: move this pruning to after finalization confirmations, not here!
        let inblock = true;
        author
            .remove_top(
                vec![TrustedOperationOrHash::Operation(
                    stf_call_signed.clone().into_trusted_operation(true),
                )],
                shard,
                inblock,
            )
            .unwrap();
    }
    // convert trusted call signed to trusted operation before hashing
    // ATTENTION: only valid for direct calls. In case of indirect
    // one should think this over.
    let operation = stf_call_signed.into_trusted_operation(true);
    let call_hash = blake2_256(&operation.encode());
    debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

    Ok(Some(H256::from(call_hash)))
}

fn verify_worker_responses(
    responses: Vec<WorkerResponse<Vec<u8>>>,
    header: Header,
) -> SgxResult<HashMap<Vec<u8>, Option<Vec<u8>>>> {
    let mut update_map = HashMap::new();
    for response in responses.iter() {
        match response {
            WorkerResponse::ChainStorage(key, value, proof) => {
                let proof = proof
                    .as_ref()
                    .sgx_error_with_log("No Storage Proof Supplied")?;

                let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
                    header.state_root,
                    key,
                    proof.to_vec(),
                )
                .sgx_error_with_log("Erroneous StorageProof")?;

                // Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
                if &actual != value {
                    error!("Wrong storage value supplied");
                    return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
                }
                update_map.insert(key.clone(), value.clone());
            }
        }
    }
    Ok(update_map)
}

extern "C" {
    pub fn ocall_read_ipfs(
        ret_val: *mut sgx_status_t,
        cid: *const u8,
        cid_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_write_ipfs(
        ret_val: *mut sgx_status_t,
        enc_state: *const u8,
        enc_state_size: u32,
        cid: *mut u8,
        cid_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_worker_request(
        ret_val: *mut sgx_status_t,
        request: *const u8,
        req_size: u32,
        response: *mut u8,
        resp_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;

    pub fn ocall_send_block_and_confirmation(
        ret_val: *mut sgx_status_t,
        confirmations: *const u8,
        confirmations_size: u32,
        signed_blocks: *const u8,
        signed_blocks_size: u32,
    ) -> sgx_status_t;

}

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
        //top_pool::pool::test_should_reject_if_temporarily_banned,
        top_pool::pool::test_should_notify_about_pool_events,
        //top_pool::pool::test_should_clear_stale_transactions,
        //top_pool::pool::test_should_ban_mined_transactions,
        //top_pool::pool::test_should_limit_futures,
        top_pool::pool::test_should_error_if_reject_immediately,
        top_pool::pool::test_should_reject_transactions_with_no_provides,
        /*top_pool::pool::listener::test_should_trigger_ready_and_finalized,
        top_pool::pool::listener::test_should_trigger_ready_and_finalized_when_pruning_via_hash,
        top_pool::pool::listener::test_should_trigger_future_and_ready_after_promoted,
        top_pool::pool::listener::test_should_trigger_invalid_and_ban,
        top_pool::pool::listener::test_should_trigger_broadcasted,
        top_pool::pool::listener::test_should_trigger_dropped,
        top_pool::pool::listener::test_should_handle_pruning_in_the_middle_of_import,*/
        state::test_encrypted_state_io_works,
        state::test_write_and_load_state_works,
        state::test_sgx_state_decode_encode_works,
        state::test_encrypt_decrypt_state_type_works,
        test_time_is_overdue,
        test_time_is_not_overdue,
        test_compose_block_and_confirmation,
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

use jsonrpc_core::futures::executor;
use sp_core::ed25519 as spEd25519;
use substratee_stf::{TrustedGetter, TrustedOperation};
/// tests
//use substrate_test_runtime::{AccountId};
//use crate::top_pool::base_pool::Limit;
//use std::sync::SgxMutex as Mutex;
//use substratee_stf::{TrustedCall, TrustedCallSigned, TrustedOperation};
//use top_pool::primitives::from_low_u64_to_be_h256;

fn test_ocall_read_write_ipfs() {
    info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut cid_buf: Vec<u8> = vec![0; 46];
    let enc_state: Vec<u8> = vec![20; 4 * 512 * 1024];

    let _res = unsafe {
        ocall_write_ipfs(
            &mut rt as *mut sgx_status_t,
            enc_state.as_ptr(),
            enc_state.len() as u32,
            cid_buf.as_mut_ptr(),
            cid_buf.len() as u32,
        )
    };

    let res = unsafe {
        ocall_read_ipfs(
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

// TODO: this is redundantly defined in worker/src/main.rs
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerRequest {
    ChainStorage(Vec<u8>, Option<Hash>), // (storage_key, at_block)
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerResponse<V: Encode + Decode> {
    ChainStorage(Vec<u8>, Option<V>, Option<Vec<Vec<u8>>>), // (storage_key, storage_value, storage_proof)
}

fn worker_request<V: Encode + Decode>(
    req: Vec<WorkerRequest>,
) -> SgxResult<Vec<WorkerResponse<V>>> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut resp: Vec<u8> = vec![0; 4196 * 4];

    let res = unsafe {
        ocall_worker_request(
            &mut rt as *mut sgx_status_t,
            req.encode().as_ptr(),
            req.encode().len() as u32,
            resp.as_mut_ptr(),
            resp.len() as u32,
        )
    };

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }
    Ok(Decode::decode(&mut resp.as_slice()).unwrap())
}

// tests
use sgx_externalities::SgxExternalitiesTrait;

fn test_ocall_worker_request() {
    info!("testing ocall_worker_request. Hopefully substraTEE-node is running...");
    let mut requests = Vec::new();

    requests.push(WorkerRequest::ChainStorage(
        storage_key("Balances", "TotalIssuance").0,
        None,
    ));

    let mut resp: Vec<WorkerResponse<Vec<u8>>> = match worker_request(requests) {
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

fn test_time_is_overdue() {
    // given
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // when
    let before_start_time = (start_time * 1000 - GETTERTIMEOUT) / 1000;
    let time_has_run_out = time_is_overdue(Timeout::Getter, before_start_time);
    // then
    assert!(time_has_run_out)
}

fn test_time_is_not_overdue() {
    // given
    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // when
    let time_has_run_out = time_is_overdue(Timeout::Call, start_time);
    // then
    assert!(!time_has_run_out)
}

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
    let mut state = StfState::new();
    Stf::update_block_number(&mut state, 1);

    // when
    let (opaque_call, signed_block) = compose_block_and_confirmation(
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
    assert_eq!(signed_block.block().block_number(), 2);
    assert!(opaque_call_vec.starts_with(&xt_block_encoded));
    let mut stripped_opaque_call = opaque_call_vec.split_off(xt_block_encoded.len());
    assert!(stripped_opaque_call.starts_with(&shard.encode()));
    let stripped_opaque_call = stripped_opaque_call.split_off(shard.encode().len());
    assert!(stripped_opaque_call.starts_with(&block_hash_encoded));
}

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
    // load state before executing any calls
    let _state = if state::exists(&shard) {
        state::load(&shard).unwrap()
    } else {
        state::init_shard(&shard).unwrap();
        Stf::init_state()
    };
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

fn test_submit_trusted_getter_to_top_pool() {
    // given

    // create top pool
    let api: Arc<FillerChainApi<Block>> = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(Default::default(), api);
    let author = Author::new(Arc::new(&tx_pool));

    // create trusted getter signed
    let shard = ShardIdentifier::default();
    // load state before executing any calls
    let _state = if state::exists(&shard) {
        state::load(&shard).unwrap()
    } else {
        state::init_shard(&shard).unwrap();
        Stf::init_state()
    };
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

fn test_differentiate_getter_and_call_works() {
    // given

    // create top pool
    let api: Arc<FillerChainApi<Block>> = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(Default::default(), api);
    let author = Author::new(Arc::new(&tx_pool));
    // create trusted getter signed
    let shard = ShardIdentifier::default();
    // load state before executing any calls
    let _state = if state::exists(&shard) {
        state::load(&shard).unwrap()
    } else {
        state::init_shard(&shard).unwrap();
        Stf::init_state()
    };
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

#[allow(unused_assignments)]
fn test_create_block_and_confirmation_works() {
    // given

    // create top pool
    unsafe { rpc::worker_api_direct::initialize_pool() };
    let shard = ShardIdentifier::default();
    // load state before executing any calls
    let _state = if state::exists(&shard) {
        state::load(&shard).unwrap()
    } else {
        state::init_shard(&shard).unwrap();
        Stf::init_state()
    };
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
    let (confirm_calls, signed_blocks) = execute_top_pool_calls(latest_onchain_header).unwrap();

    let signed_block = signed_blocks[0].clone();
    let mut opaque_call_vec = confirm_calls[0].0.clone();
    let xt_block_encoded = [SUBSRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED].encode();
    let block_hash_encoded = blake2_256(&signed_block.block().encode()).encode();

    // then
    assert_eq!(signed_blocks.len(), 1);
    assert_eq!(confirm_calls.len(), 1);
    assert!(signed_block.verify_signature());
    assert_eq!(signed_block.block().block_number(), 1);
    assert_eq!(signed_block.block().signed_top_hashes()[0], top_hash);
    assert!(opaque_call_vec.starts_with(&xt_block_encoded));
    let mut stripped_opaque_call = opaque_call_vec.split_off(xt_block_encoded.len());
    assert!(stripped_opaque_call.starts_with(&shard.encode()));
    let stripped_opaque_call = stripped_opaque_call.split_off(shard.encode().len());
    assert!(stripped_opaque_call.starts_with(&block_hash_encoded));
}

//FIXME: Finish state diff unittest. Current problem: Set balance of test account
fn test_create_state_diff() {
    // given

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
    let rsa_pair = rsa3072::unseal_pair().unwrap();

    // ensure that state exists
    let state = if state::exists(&shard) {
        state::load(&shard).unwrap()
    } else {
        state::init_shard(&shard).unwrap();
        Stf::init_state()
    };

    // create accountss
    let signer_without_money = ed25519::unseal_pair().unwrap();
    let pair_with_money = spEd25519::Pair::from_seed(b"12345678901234567890123456789012");
    let account_with_money = pair_with_money.public();
    let account_without_money = signer_without_money.public();

    let prev_state_hash = state::write(state.clone(), &shard).unwrap();
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
            0,
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
    let (_, signed_blocks) = execute_top_pool_calls(latest_onchain_header).unwrap();
    let mut encrypted_payload: Vec<u8> = signed_blocks[0].block().state_payload().to_vec();
    aes::de_or_encrypt(&mut encrypted_payload).unwrap();
    let state_payload = StatePayload::decode(&mut encrypted_payload.as_slice()).unwrap();
    let state_diff = StfStateTypeDiff::decode(state_payload.state_update().to_vec());
}
