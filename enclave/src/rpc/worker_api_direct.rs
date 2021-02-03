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
  string::{ToString, String},
  str,
  format,
  slice::{from_raw_parts, from_raw_parts_mut},
  vec::Vec,
  borrow::ToOwned,
};

use core::{
  result::Result,
  ops::Deref,
};

use sgx_types::*;
use sgx_tstd::{
  sync::{SgxMutex, Arc},
  sync::atomic::{AtomicPtr, Ordering},
};

use sp_core::H256 as Hash;

use codec::Decode;
use log::*;

use crate::rpc::{
  author::{Author, AuthorApi},
  api::FillerChainApi,
  basic_pool::BasicPool,
};

use crate::transaction_pool::{
  pool::Options as PoolOptions,
};

use jsonrpc_core::*;
use jsonrpc_core::futures::executor;
use jsonrpc_core::Error as RpcError;
use serde::Deserialize;

use substratee_stf::{ShardIdentifier};

use chain_relay::Block; 
use base58::FromBase58;

use crate::utils::{write_slice_and_whitespace_pad};

static GLOBAL_TX_POOL: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

#[no_mangle]
// initialise tx pool and store within static atomic pointer
pub unsafe extern "C" fn initialize_pool() -> sgx_status_t {

    let api = Arc::new(FillerChainApi::new());
    let tx_pool = BasicPool::create(PoolOptions::default(), api);   
    let pool_ptr = Arc::new(SgxMutex::<BasicPool<FillerChainApi<Block>, Block>>::new(tx_pool));
    let ptr = Arc::into_raw(pool_ptr);
    GLOBAL_TX_POOL.store(ptr as *mut (), Ordering::SeqCst);

    sgx_status_t::SGX_SUCCESS
}

pub fn load_tx_pool() -> Option<&'static SgxMutex<BasicPool<FillerChainApi<Block>, Block>>>
{
    let ptr = GLOBAL_TX_POOL.load(Ordering::SeqCst) as * mut SgxMutex<BasicPool<FillerChainApi<Block>, Block>>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn convert_vec_to_string(vec_methods: Vec<&str>) -> String {
    let mut method_string = String::new();
    for i in 0..vec_methods.len()  {
        method_string.push_str(vec_methods[i]);
        if vec_methods.len() > (i+1) {
            method_string.push_str(", ");
        }
    }
    format!("methods: [{}]", method_string)
}

#[derive(Deserialize)]
struct SumbitExtrinsicParams {
    call: Vec<u8>,
    shard_id: String, // ShardIdentifier (H256) does not implement deserialize
}

fn init_io_handler() -> IoHandler {
    let mut io = IoHandler::new();
    let mut rpc_methods_vec: Vec<&str> = Vec::new();

    // Add rpc methods    
    // author_submitAndWatchExtrinsic 
    let author_submit_and_watch_extrinsic_name: &str = "author_submitAndWatchExtrinsic";
    rpc_methods_vec.push(author_submit_and_watch_extrinsic_name);
    io.add_sync_method(author_submit_and_watch_extrinsic_name, move |params: Params| {  
       match params.parse() {
            Ok(ok) => {   
                let parsed: SumbitExtrinsicParams = ok;
              /*  let result = async {              
                  author_clone.submit_extrinsic(tx.extrinsic.clone()).await
                };      */          
                Ok(Value::String(format!("hello extrinsic, {}", String::from_utf8(parsed.call).unwrap())))
            },
            Err(e) => Ok(Value::String(format!("author_submitAndWatchExtrinsic not called due to {}", e))),
         }
    });

    // author_submitExtrinsic
    let author_submit_extrinsic_name: &str = "author_submitExtrinsic";
    rpc_methods_vec.push(author_submit_extrinsic_name);
    io.add_sync_method(author_submit_extrinsic_name, move |params: Params| {      
		  match params.parse() {
        Ok(extrinsic) => {
          // Aquire lock
          let &ref tx_pool_mutex = load_tx_pool().unwrap();
          let tx_pool_guard = tx_pool_mutex.lock().unwrap();
          let tx_pool = Arc::new(tx_pool_guard.deref());
          let author = Author::new(tx_pool); 

          let to_submit: SumbitExtrinsicParams = extrinsic;
          let shard_vec = match to_submit.shard_id.from_base58() {
            Ok(vec) => vec,
            Err(_) => return Ok(Value::String(format!("Invalid base58 format of shard id"))),
          };
          let shard = match ShardIdentifier::decode(&mut shard_vec.as_slice()) {
              Ok(hash) => hash,
              Err(_) => return Ok(Value::String(format!("Shard ID is not of type H256"))),
          };
          let result = async {              
            author.submit_call(to_submit.call.clone(), shard).await
          };     
          let response: Result<Hash, RpcError> = executor::block_on(result);
          match response {
            Ok(hash_value) => Ok(Value::String(format!("The following trusted call was submitted: {}", hash_value.to_string()))),
            Err(rpc_error) => Ok(Value::String(format!("Error: {}", rpc_error.message))),
          }          
        },
        Err(e) => Ok(Value::String(format!("Could not submit trust call due to: {}", e))),
     }
    });
    
    // author_pendingExtrinsics  
    let author_pending_extrinsic_name: &str = "author_pendingExtrinsics";
    rpc_methods_vec.push(author_pending_extrinsic_name);
    io.add_sync_method(author_pending_extrinsic_name, move |params: Params| {
      match params.parse::<Vec<String>>() {
          Ok(shards) => { 
            // Aquire tx_pool lock           
            let &ref tx_pool_mutex = load_tx_pool().unwrap();
            let tx_pool_guard = tx_pool_mutex.lock().unwrap();
            let tx_pool = Arc::new(tx_pool_guard.deref());
            let author = Author::new(tx_pool); 

            let mut retrieved_calls = vec![];
            for shard_base58 in shards.iter() {
              let shard_encoded = match shard_base58.from_base58() {
                Ok(vec) => vec,
                Err(_) => return Ok(Value::String(format!("Invalid base58 format of shard id {:?}", shard_base58))),
              };
              let shard = match ShardIdentifier::decode(&mut shard_encoded.as_slice()) {
                  Ok(hash) => hash,
                  Err(_) => return Ok(Value::String(format!("Shard {:?} is not of type H256", shard_base58))),
              };
              let result: Result<Vec<Vec<u8>>, _> = author.pending_calls(shard);
              if let Ok(vec_of_calls) = result {
                retrieved_calls.push(vec_of_calls);
              }            
            }
            Ok(Value::String(format!("Pending Extrinsics: {:?}", retrieved_calls)))
          }
        Err(e) => Ok(Value::String(format!("Could not retrieve pending calls due to: {}", e))),
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
    io.add_sync_method("rpc_methods", move |_: Params| Ok(Value::String(rpc_methods_string.to_owned())));
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
    let mut response_string = String::new();
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
    // get rpc response
    response_string = io.handle_request_sync(request_string).unwrap().to_string();
    debug!{"Released Txpool Lock"};
    
    // update response outside of enclave
    let response_slice = from_raw_parts_mut(response, response_len as usize);
    write_slice_and_whitespace_pad(response_slice, response_string.as_bytes().to_vec());
	sgx_status_t::SGX_SUCCESS
}