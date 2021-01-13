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
  str::from_utf8,
  format,
  slice::{from_raw_parts, from_raw_parts_mut},
  vec::Vec,
  borrow::ToOwned,
  boxed::Box,
  sync::Arc,
};

use core::{
  iter::Iterator,
  hash,
};

use sgx_types::*;
use sgx_tstd::error;

use log::*;
use sp_core::storage::{StorageKey, StorageData, StorageChangeSet};
use sp_runtime::generic;

use crate::rpc::{
  error::{DenyUnsafe, FutureResult},
  author::Author,
  test_api::TestApi,
};

use crate::transaction_pool::{
  pool::{ExtrinsicHash, ExtrinsicFor, NumberFor, ValidatedTransactionFor, 
    ChainApi, BlockHash, Pool, Options as PoolOptions},
  error as txError,
};

use jsonrpc_core::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct SumbitExtrinsicParams {
    extrinsic: String,
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

fn init_io_handler() -> IoHandler {
    let mut io = IoHandler::new();
    let mut rpc_methods_vec: Vec<&str> = Vec::new();    
    let api = TestApi::default();
    let options = PoolOptions::default();
    let tx_pool: Pool<TestApi> = Pool::new(options, api.into());
    
    //let request_test = r#"{"jsonrpc": "2.0", "method": "say_hello", "params": [42, 23], "id": 1}"#;

    /// Add rpc methods
    
    // author_submitAndWatchExtrinsic
    let author_submit_and_watch_extrinsic_name: &str = "author_submitAndWatchExtrinsic";
    rpc_methods_vec.push(author_submit_and_watch_extrinsic_name);
    io.add_sync_method(author_submit_and_watch_extrinsic_name, |params: Params| {  
       match params.parse() {
            Ok(ok) => {
                let parsed: SumbitExtrinsicParams = ok;
                Ok(Value::String(format!("hello extrinsic, {}", parsed.extrinsic)))
            },
            Err(e) => Ok(Value::String(format!("author_submitAndWatchExtrinsic not called due to {}", e))),
         }
    });

    // author_submitExtrinsic
    let author_submit_extrinsic_name: &str = "author_submitExtrinsic";
    rpc_methods_vec.push(author_submit_extrinsic_name);
    io.add_sync_method(author_submit_extrinsic_name, |params: Params| {
		  match params.parse() {
        Ok(call) => {
            let tx: SumbitExtrinsicParams = call;
         //   let result: FutureResult<Hash> = author_api.submit_extrinsic(tx.extrinsic);
            Ok(Value::String(format!("hello extrinsic, {}", tx.extrinsic)))
        },
        Err(e) => Ok(Value::String(format!("author_submitExtrinsic not called due to {}", e))),
     }
    });
    
    // author_pendingExtrinsics
    let author_pending_extrinsic_name: &str = "author_pendingExtrinsics";
    rpc_methods_vec.push(author_pending_extrinsic_name);
    io.add_sync_method(author_pending_extrinsic_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
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
    let request_string = match from_utf8(&req) {
       Ok(req) => req,
       Err(e) => {
            error!("Decoding Header failed. Error: {:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }  
    };
    // get rpc response
    response_string = io.handle_request_sync(request_string).unwrap().to_string();
    
    // update response outside of enclave
    let response_slice = from_raw_parts_mut(response, response_len as usize);
    write_slice_and_whitespace_padding(response_slice, response_string.as_bytes().to_vec());
	sgx_status_t::SGX_SUCCESS
}

// necessary to redefine due to no-std obligation
pub fn write_slice_and_whitespace_padding(writable: &mut [u8], data: Vec<u8>) {
    if data.len() > writable.len() {
        panic!("not enough bytes in output buffer for return value");
    }
    let (left, right) = writable.split_at_mut(data.len());
    left.clone_from_slice(&data);
    // fill the right side with whitespace
    right.iter_mut().for_each(|x| *x = 0x20);
}