
pub extern crate alloc;
use alloc::string::{String, ToString};
use alloc::str::from_utf8;
use alloc::slice::{from_raw_parts, from_raw_parts_mut};
use core::iter::Iterator;
use alloc::vec::Vec;

use sgx_types::*;

use log::*;
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Stream};

use jsonrpc_core::{Error, IoHandler, Result};

use crate::aes;
use crate::attestation::{create_ra_report_and_signature, DEV_HOSTNAME};
use crate::cert;
use crate::rsa3072;

//extern crate json_rpc_core;
//extern crate json_rpc;
/*use json_rpc::{Server, Json, Error};

use substrate_api_client::{utils::hexstr_to_vec, Api, XtStatus};
use substratee_node_runtime::{
    substratee_registry::ShardIdentifier, Event, Hash, Header, SignedBlock, UncheckedExtrinsic,
};

#[rpc]
pub trait AuthorRpc {
    #[rpc(name = "author_submitExtrinsic")]
    fn silly_7(&self) -> Result<u64>;
}

pub struct Author;

impl AuthorRpc for Author {
    fn silly_7(&self) -> Result<u64> {
        Ok(7)
    }


}

fn add(&self, a: u64, b: u64) -> Result<u64> {
	Ok(a + b)
}
*/

#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
    request: *const u8,
    request_len: u32,
    response: *mut u8,
    response_len: u32,
) -> sgx_status_t {

   let req = from_raw_parts(request, request_len as usize);
   let request_string = match from_utf8(req) {
       Ok(req) => req.to_string(),
       Err(_) => String::from("Empty"),
   };
    
   let mut response_string = "test".to_string();
    if request_string.contains("method") {
        response_string = "[Enclave] found".to_string();
    } else {
        response_string = "[Enclave] not found".to_string();
    }

    
  // let response = response_string.as_bytes();
    let response_slice = from_raw_parts_mut(response, response_len as usize);
   write_slice_and_whitespace_padding(response_slice, response_string.as_bytes().to_vec());

    
    //response.clone_from_slice(&response.to_vec());
	//let mut io = IoHandler::new();
	//io.extend_with()
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
