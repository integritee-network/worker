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
use substratee_node_primitives::{CallWorkerFn, ShieldFundsFn};

use codec::{Decode, Encode};
use sp_core::{crypto::Pair, hashing::blake2_256};
use sp_finality_grandpa::VersionedAuthorityList;

use constants::{
    CALL_CONFIRMED, RUNTIME_SPEC_VERSION, RUNTIME_TRANSACTION_VERSION, SUBSRATEE_REGISTRY_MODULE,
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
use substratee_stf::sgx::{shards_key_hash, storage_hashes_to_update_per_shard, OpaqueCall};
use substratee_stf::{AccountId, Getter, ShardIdentifier, Stf, TrustedCall,
     TrustedCallSigned, TrustedGetterSigned};

use rpc::author::{hash::TrustedOperationOrHash, Author, AuthorApi};
use rpc::{api::FillerChainApi, basic_pool::BasicPool};
use rpc::worker_api_direct;

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

fn stf_post_actions(
    mut validator: LightValidation,
    calls_buffer: Vec<OpaqueCall>,
    extrinsics_slice: &mut [u8],
    mut nonce: u32,
) -> SgxResult<()> {
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

    for xt in extrinsics_buffer.iter() {
        validator
            .submit_xt_to_be_included(
                validator.num_relays,
                OpaqueExtrinsic::from_bytes(xt.as_slice()).unwrap(),
            )
            .unwrap();
    }

    write_slice_and_whitespace_pad(extrinsics_slice, extrinsics_buffer.encode());

    io::light_validation::seal(validator)?;

    Ok(())
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

    let latest_header = validator.latest_header(validator.num_relays).unwrap();

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
pub unsafe extern "C" fn sync_chain_relay(
    blocks: *const u8,
    blocks_size: usize,
    nonce: *const u32,
    unchecked_extrinsic: *mut u8,
    unchecked_extrinsic_size: usize,
) -> sgx_status_t {
    debug!("Syncing chain relay!");
    let mut blocks_slice = slice::from_raw_parts(blocks, blocks_size);
    let xt_slice = slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size);

    let blocks: Vec<SignedBlock<Block>> = match Decode::decode(&mut blocks_slice) {
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

    // get header of last block
    let last_block_header: Header = blocks.last().unwrap().block.header.clone();

    let mut calls = Vec::new();
    for signed_block in blocks.into_iter() {
        validator
            .check_xt_inclusion(validator.num_relays, &signed_block.block)
            .unwrap(); // panic can only happen if relay_id is does not exist
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

        match scan_block_for_relevant_xt(&signed_block.block) {
            Ok(c) => calls.extend(c.into_iter()),
            Err(_) => error!("Error executing relevant extrinsics"),
        };
    }
    // execute pending calls from operation pool
    match execute_top_pool_calls(last_block_header) {
        Ok(c) => calls.extend(c.into_iter()),
        Err(_) => error!("Error executing relevant tx pool calls"),
    };

    if let Err(_e) = stf_post_actions(validator, calls, xt_slice, *nonce) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    sgx_status_t::SGX_SUCCESS
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
            return None
        },
    };

    debug!("calling into STF to get state");
    Stf::get_state(&mut state, trusted_getter_signed.into())

}

fn execute_top_pool_calls(header: Header) -> SgxResult<Vec<OpaqueCall>> {
    debug!("Executing pending pool operations");
    let mut calls = Vec::<OpaqueCall>::new();
    {
        let &ref pool_mutex: &SgxMutex<BPool> = rpc::worker_api_direct::load_top_pool().unwrap();
        let pool_guard: SgxMutexGuard<BPool> = pool_mutex.lock().unwrap();
        let pool: Arc<&BPool> = Arc::new(pool_guard.deref());
        let author: Arc<Author<&BPool>> = Arc::new(Author::new(pool));

        // get all shards with tx pool of worker
        let shards: Vec<ShardIdentifier> = author.get_shards();

        for shard in shards.into_iter() {
            // retrieve trusted operations from pool
            let (trusted_calls, trusted_getters) = match author.pending_tops_separated(shard) {
                Ok((calls,getters)) => (calls,getters),
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
                if let Err(e) = author.remove_top(vec![TrustedOperationOrHash::Hash(hash_of_getter)], shard, false) {
                    error!("Error removing trusted operation from top pool: Error: {:?}", e);
                }
            }
            for trusted_call_signed in trusted_calls.into_iter() {
                if let Err(e) = handle_trusted_worker_call(
                    &mut calls,
                    trusted_call_signed,
                    header.clone(),
                    shard,
                    Some(author.clone()),
                ) {
                    error!("Error performing worker call: Error: {:?}", e);
                }
            }            
        }
    }

    Ok(calls)
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
                    Stf::update_block_number(&mut state, header.number);

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

        if let Ok(xt) =
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
        }
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

fn decrypt_unchecked_extrinsic(
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

fn handle_trusted_worker_call(
    calls: &mut Vec<OpaqueCall>,
    stf_call_signed: TrustedCallSigned,
    header: Header,
    shard: ShardIdentifier,
    author_pointer: Option<Arc<Author<&BPool>>>,
) -> SgxResult<()> {
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
                    vec![TrustedOperationOrHash::Operation(stf_call_signed.into_trusted_operation(true))],
                    shard,
                    inblock,
                )
                .unwrap();
        }
        return Ok(());
    }

    let mut state = if state::exists(&shard) {
        state::load(&shard)?
    } else {
        state::init_shard(&shard)?;
        Stf::init_state()
    };

    debug!("Update STF storage!");
    let requests = Stf::get_storage_hashes_to_update(&stf_call_signed)
        .into_iter()
        .map(|key| WorkerRequest::ChainStorage(key, Some(header.hash())))
        .collect();

    let responses: Vec<WorkerResponse<Vec<u8>>> = worker_request(requests)?;

    let update_map = verify_worker_responses(responses, header)?;

    Stf::update_storage(&mut state, &update_map);

    debug!("execute STF");
    if let Err(e) = Stf::execute(&mut state, stf_call_signed.clone(), calls) {
        if let Some(author) = author_pointer {
            // remove call as invalid from pool
            let inblock = false;
            author
                .remove_top(
                    vec![TrustedOperationOrHash::Operation(stf_call_signed.into_trusted_operation(true))],
                    shard,
                    inblock,
                )
                .unwrap();
        }
        error!("Error performing Stf::execute. Error: {:?}", e);

        return Ok(());
    }

    if let Some(author) = author_pointer {
        // TODO: prune instead of remove_top ? Block needs to be known
        // remove call from pool as valid
        let inblock = true;
        author
            .remove_top(
                vec![TrustedOperationOrHash::Operation(stf_call_signed
                    .clone()
                    .into_trusted_operation(true)
                )],
                shard,
                inblock,
            )
            .unwrap();
    }

    let state_hash = state::write(state, &shard)?;

    let xt_call = [SUBSRATEE_REGISTRY_MODULE, CALL_CONFIRMED];
    let call_hash = blake2_256(&stf_call_signed.encode());
    debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

    calls.push(OpaqueCall(
        (xt_call, shard, call_hash, state_hash.encode()).encode(),
    ));

    Ok(())
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
}

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
    rsgx_unit_tests!(
        state::test_encrypted_state_io_works,
        ipfs::test_creates_ipfs_content_struct_works,
        ipfs::test_verification_ok_for_correct_content,
        ipfs::test_verification_fails_for_incorrect_content,
        test_ocall_read_write_ipfs,
        test_ocall_worker_request
    )
}

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
