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
use alloc::string::ToString;
use alloc::str::from_utf8;
use alloc::slice::{from_raw_parts, from_raw_parts_mut};
use core::iter::Iterator;
use alloc::vec::Vec;
use alloc::borrow::ToOwned;

use sgx_types::*;

use log::*;

use jsonrpc_core::*;

#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
    request: *const u8,
    request_len: u32,
    response: *mut u8,
    response_len: u32,
) -> sgx_status_t {

    let mut io = IoHandler::new();
    let mut response_string = "test".to_string();

    io.add_sync_method("say_hello", |_: Params| Ok(Value::String("Hello World!".to_owned())));

    let req: Vec<u8> = from_raw_parts(request, request_len as usize).to_vec(); 
    let request_string = match from_utf8(&req) {
       Ok(req) => req,
       Err(_) => "Empty",
    };

    //let request_test = r#"{"jsonrpc": "2.0", "method": "say_hello", "params": [42, 23], "id": 1}"#;
    response_string = io.handle_request_sync(request_string).unwrap().to_string();

   
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
