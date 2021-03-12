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

pub extern crate alloc;
use alloc::{
    borrow::ToOwned,
    format,
    slice::{from_raw_parts, from_raw_parts_mut},
    str,
    string::{String, ToString},
    vec::Vec,
};
use core::{ops::Deref, result::Result};

use std::{
    sync::atomic::{AtomicPtr, Ordering},
    sync::{Arc, SgxMutex},
};
use sgx_types::*;

use sp_core::H256 as Hash;

use codec::{Decode, Encode};
use log::*;

use crate::rpc::{
    api::FillerChainApi,
    author::{Author, AuthorApi},
    basic_pool::BasicPool,
};

use crate::top_pool::pool::Options as PoolOptions;

use jsonrpc_core::futures::executor;
use jsonrpc_core::Error as RpcError;
use jsonrpc_core::*;
use serde_json::*;

use substratee_stf::ShardIdentifier;

use base58::FromBase58;
use chain_relay::Block;

use substratee_node_primitives::Request;
use substratee_worker_primitives::RpcReturnValue;
use substratee_worker_primitives::{TrustedOperationStatus, DirectCallStatus};

use crate::utils::write_slice_and_whitespace_pad;
use crate::rsa3072;

static GLOBAL_TX_POOL: AtomicPtr<()> = AtomicPtr::new(0 as *mut ());

extern "C" {
    pub fn ocall_update_status_event(
        ret_val: *mut sgx_status_t,
        hash_encoded: *const u8,
        hash_size: u32,
        status_update_encoded: *const u8,
        status_size: u32,
    ) -> sgx_status_t;
    pub fn ocall_send_status(
        ret_val: *mut sgx_status_t,
        hash_encoded: *const u8,
        hash_size: u32,
        status_update_encoded: *const u8,
        status_size: u32,
    ) -> sgx_status_t;
}

#[no_mangle]
// initialise tx pool and store within static atomic pointer
pub unsafe extern "C" fn initialize_pool() -> sgx_status_t {
    let api = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(PoolOptions::default(), api);
    let pool_ptr = Arc::new(SgxMutex::<BasicPool<FillerChainApi<Block>, Block>>::new(
        tx_pool,
    ));
    let ptr = Arc::into_raw(pool_ptr);
    GLOBAL_TX_POOL.store(ptr as *mut (), Ordering::SeqCst);

    sgx_status_t::SGX_SUCCESS
}

pub fn load_top_pool() -> Option<&'static SgxMutex<BasicPool<FillerChainApi<Block>, Block>>> {
    let ptr = GLOBAL_TX_POOL.load(Ordering::SeqCst)
        as *mut SgxMutex<BasicPool<FillerChainApi<Block>, Block>>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn convert_vec_to_string(vec_methods: Vec<&str>) -> String {
    let mut method_string = String::new();
    for i in 0..vec_methods.len() {
        method_string.push_str(vec_methods[i]);
        if vec_methods.len() > (i + 1) {
            method_string.push_str(", ");
        }
    }
    format!("methods: [{}]", method_string)
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn decode_shard_from_base58(shard_base58: String) -> Result<ShardIdentifier, String> {
    let shard_vec = match shard_base58.from_base58() {
        Ok(vec) => vec,
        Err(_) => return Err("Invalid base58 format of shard id".to_owned()),
    };
    let shard = match ShardIdentifier::decode(&mut shard_vec.as_slice()) {
        Ok(hash) => hash,
        Err(_) => return Err("Shard ID is not of type H256".to_owned()),
    };
    Ok(shard)
}

fn compute_encoded_return_error(error_msg: String) -> Vec<u8> {
    let return_value = RpcReturnValue {
        value: error_msg.encode(),
        do_watch: false,
        status: DirectCallStatus::Error,
    };
    return_value.encode()
}

fn init_io_handler() -> IoHandler {
    let mut io = IoHandler::new();
    let mut rpc_methods_vec: Vec<&str> = Vec::new();

    // Add rpc methods
    // author_submitAndWatchExtrinsic
    let author_submit_and_watch_extrinsic_name: &str = "author_submitAndWatchExtrinsic";
    rpc_methods_vec.push(author_submit_and_watch_extrinsic_name);
    io.add_sync_method(
        author_submit_and_watch_extrinsic_name,
        move |params: Params| {
            match params.parse::<Vec<u8>>() {
                Ok(encoded_params) => {
                    // Aquire lock
                    let &ref tx_pool_mutex = load_top_pool().unwrap();
                    let tx_pool_guard = tx_pool_mutex.lock().unwrap();
                    let tx_pool = Arc::new(tx_pool_guard.deref());
                    let author = Author::new(tx_pool);

                    match Request::decode(&mut encoded_params.as_slice()) {
                        Ok(request) => {
                            let shard: ShardIdentifier = request.shard;
                            let encrypted_trusted_call: Vec<u8> = request.cyphertext;
                            let result = async {
                                author
                                    .watch_top(encrypted_trusted_call.clone(), shard)
                                    .await
                            };
                            let response: Result<Hash, RpcError> = executor::block_on(result);
                            let json_value = match response {
                                Ok(hash_value) => {
                                    RpcReturnValue {
                                        do_watch: true,
                                        value: hash_value.encode(),
                                        status: DirectCallStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted),
                                    }.encode()
                                },
                                Err(rpc_error) => compute_encoded_return_error(rpc_error.message)
                            };
                            Ok(json!(json_value))
                        }
                        Err(_) => Ok(json!(compute_encoded_return_error(
                            "Could not decode request".to_owned()
                        ))),
                    }
                }
                Err(e) => {
                    let error_msg: String = format!("Could not submit trusted call due to: {}", e);
                    Ok(json!(compute_encoded_return_error(error_msg)))
                }
            }
        },
    );

    // author_submitExtrinsic
    let author_submit_extrinsic_name: &str = "author_submitExtrinsic";
    rpc_methods_vec.push(author_submit_extrinsic_name);
    io.add_sync_method(author_submit_extrinsic_name, move |params: Params| {
        match params.parse::<Vec<u8>>() {
            Ok(encoded_params) => {
                // Aquire lock
                let &ref tx_pool_mutex = load_top_pool().unwrap();
                let tx_pool_guard = tx_pool_mutex.lock().unwrap();
                let tx_pool = Arc::new(tx_pool_guard.deref());
                let author = Author::new(tx_pool);

                match Request::decode(&mut encoded_params.as_slice()) {
                    Ok(request) => {
                        let shard: ShardIdentifier = request.shard;
                        let encrypted_trusted_op: Vec<u8> = request.cyphertext;
                        let result = async {
                            author
                                .submit_top(encrypted_trusted_op.clone(), shard)
                                .await
                        };
                        let response: Result<Hash, RpcError> = executor::block_on(result);
                        let json_value = match response {
                            Ok(hash_value) => {
                                RpcReturnValue {
                                    do_watch: false,
                                    value: hash_value.encode(),
                                    status: DirectCallStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted),
                                }.encode()
                            },
                            Err(rpc_error) => compute_encoded_return_error(rpc_error.message)
                        };
                        Ok(json!(json_value))
                    }
                    Err(_) => Ok(json!(compute_encoded_return_error(
                        "Could not decode request".to_owned()
                    ))),
                }
            }
            Err(e) => {
                let error_msg: String = format!("Could not submit trusted call due to: {}", e);
                Ok(json!(compute_encoded_return_error(error_msg)))
            }
        }
    });

    // author_pendingExtrinsics
    let author_pending_extrinsic_name: &str = "author_pendingExtrinsics";
    rpc_methods_vec.push(author_pending_extrinsic_name);
    io.add_sync_method(author_pending_extrinsic_name, move |params: Params| {
        match params.parse::<Vec<String>>() {
            Ok(shards) => {
                // Aquire tx_pool lock
                let &ref tx_pool_mutex = load_top_pool().unwrap();
                let tx_pool_guard = tx_pool_mutex.lock().unwrap();
                let tx_pool = Arc::new(tx_pool_guard.deref());
                let author = Author::new(tx_pool);

                let mut retrieved_operations = vec![];
                for shard_base58 in shards.iter() {
                    let shard = match decode_shard_from_base58(shard_base58.clone()) {
                        Ok(id) => id,
                        Err(msg) => return Ok(Value::String(format!("{}", msg))),
                    };
                    if let Ok(vec_of_operations) = author.pending_tops(shard) {
                        retrieved_operations.push(vec_of_operations);
                    }
                }
                let json_value = RpcReturnValue {
                            do_watch: false,
                            value: retrieved_operations.encode(),
                            status: DirectCallStatus::Ok,
                };
                Ok(json!(json_value.encode()))
            }
            Err(e) => {
                let error_msg: String = format!("Could not retrieve pending calls due to: {}", e);
                Ok(json!(compute_encoded_return_error(error_msg)))
            }
        }
    });

    // author_getShieldingKey
    let rsa_pubkey_name: &str = "author_getShieldingKey";
    rpc_methods_vec.push(rsa_pubkey_name);
    io.add_sync_method(rsa_pubkey_name, move |_: Params| {
        let rsa_pubkey = match rsa3072::unseal_pubkey() {
            Ok(key) => key,
            Err(status) => {
                let error_msg: String = format!("Could not get rsa pubkey due to: {}", status);
                return Ok(json!(compute_encoded_return_error(error_msg)))
            },
        };

        let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
            Ok(k) => k,
            Err(x) => {
                let error_msg: String = format!(
                    "[Enclave] can't serialize rsa_pubkey {:?} {}",
                    rsa_pubkey, x);
                return Ok(json!(compute_encoded_return_error(error_msg)))
            },
        };
        let json_value = RpcReturnValue::new(rsa_pubkey_json.encode(), false, DirectCallStatus::Ok);
        Ok(json!(json_value.encode()))
    });

     // system_accountNextIndex
     let system_account_next_index_name: &str = "system_accountNextIndex";
     rpc_methods_vec.push(system_account_next_index_name);
     io.add_sync_method(system_account_next_index_name, move |params: Params| {
         match params.parse::<Vec<u8>>() {
             Ok(encoded_params) => {
                 // Aquire lock
                 let &ref tx_pool_mutex = load_top_pool().unwrap();
                 let tx_pool_guard = tx_pool_mutex.lock().unwrap();
                 let tx_pool = Arc::new(tx_pool_guard.deref());
                 let author = Author::new(tx_pool);

                 match Request::decode(&mut encoded_params.as_slice()) {
                     Ok(request) => {
                         let shard: ShardIdentifier = request.shard;
                         let encrypted_account: Vec<u8> = request.cyphertext;
                         let result = async {
                             system
                                 .nonce(encrypted_account.clone(), shard)
                                 .await
                         };
                         let response: Result<Hash, RpcError> = executor::block_on(result);
                         let json_value = match response {
                             Ok(hash_value) => {
                                 RpcReturnValue {
                                     do_watch: false,
                                     value: hash_value.encode(),
                                     status: DirectCallStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted),
                                 }.encode()
                             },
                             Err(rpc_error) => compute_encoded_return_error(rpc_error.message)
                         };
                         Ok(json!(json_value))
                     }
                     Err(_) => Ok(json!(compute_encoded_return_error(
                         "Could not decode request".to_owned()
                     ))),
                 }
             }
             Err(e) => {
                 let error_msg: String = format!("Could not submit trusted call due to: {}", e);
                 Ok(json!(compute_encoded_return_error(error_msg)))
             }
         }
     });


    // chain_subscribeAllHeads
    let chain_subscribe_all_heads_name: &str = "chain_subscribeAllHeads";
    rpc_methods_vec.push(chain_subscribe_all_heads_name);
    io.add_sync_method(chain_subscribe_all_heads_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // state_getMetadata
    let state_get_metadata_name: &str = "state_getMetadata";
    rpc_methods_vec.push(state_get_metadata_name);
    io.add_sync_method(state_get_metadata_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // state_getRuntimeVersion
    let state_get_runtime_version_name: &str = "state_getRuntimeVersion";
    rpc_methods_vec.push(state_get_runtime_version_name);
    io.add_sync_method(state_get_runtime_version_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // state_get
    let state_get_name: &str = "state_get";
    rpc_methods_vec.push(state_get_name);
    io.add_sync_method(state_get_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // system_health
    let state_health_name: &str = "system_health";
    rpc_methods_vec.push(state_health_name);
    io.add_sync_method(state_health_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // system_name
    let state_name_name: &str = "system_name";
    rpc_methods_vec.push(state_name_name);
    io.add_sync_method(state_name_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // system_version
    let state_version_name: &str = "system_version";
    rpc_methods_vec.push(state_version_name);
    io.add_sync_method(state_version_name, |_: Params| {
        let parsed = "world";
        Ok(Value::String(format!("hello, {}", parsed)))
    });

    // returns all rpcs methods
    let rpc_methods_string: String = convert_vec_to_string(rpc_methods_vec);
    io.add_sync_method("rpc_methods", move |_: Params| {
        Ok(Value::String(rpc_methods_string.to_owned()))
    });

    io
}

#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
    request: *const u8,
    request_len: u32,
    response: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    // init
    let io = init_io_handler();
    // get request string
    let req: Vec<u8> = from_raw_parts(request, request_len as usize).to_vec();
    let request_string = match str::from_utf8(&req) {
        Ok(req) => req,
        Err(e) => {
            error!("Decoding Header failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    // Rpc Response String
    let response_string = io.handle_request_sync(request_string).unwrap().to_string();

    // update response outside of enclave
    let response_slice = from_raw_parts_mut(response, response_len as usize);
    write_slice_and_whitespace_pad(response_slice, response_string.as_bytes().to_vec());
    sgx_status_t::SGX_SUCCESS
}

pub fn update_status_event<H: Encode>(hash: H, status_update: TrustedOperationStatus) -> Result<(), ()> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let hash_encoded = hash.encode();
    let status_update_encoded = status_update.encode();

    let res = unsafe {
        ocall_update_status_event(
            &mut rt as *mut sgx_status_t,
            hash_encoded.as_ptr(),
            hash_encoded.len() as u32,
            status_update_encoded.as_ptr(),
            status_update_encoded.len() as u32,
        )
    };

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(());
    }

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(());
    }

    Ok(())
}


pub fn send_state<H: Encode>(hash: H, value_opt: Option<Vec<u8>>) -> Result<(), ()> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let hash_encoded = hash.encode();
    let value_encoded = value_opt.encode();

    let res = unsafe {
        ocall_send_status(
            &mut rt as *mut sgx_status_t,
            hash_encoded.as_ptr(),
            hash_encoded.len() as u32,
            value_encoded.as_ptr(),
            value_encoded.len() as u32,
        )
    };

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(());
    }

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(());
    }

    Ok(())
}