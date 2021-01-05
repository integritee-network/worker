
pub extern crate alloc;
use alloc::string::{String, ToString};
use alloc::str::from_utf8;
use alloc::slice::from_raw_parts;

use sgx_types::*;

use log::*;
use rustls::{ClientConfig, ClientSession, ServerConfig, ServerSession, Stream};

use jsonrpc_core::{Error, IoHandler, Result};

use crate::aes;
use crate::attestation::{create_ra_report_and_signature, DEV_HOSTNAME};
use crate::cert;
use crate::rsa3072;
use crate::utils::UnwrapOrSgxErrorUnexpected;

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
    response_len: *mut u32,
) -> sgx_status_t {

  let mut response_string = String::new();
   let req = from_raw_parts(request, request_len as usize);
   let request_string = match from_utf8(req) {
       Ok(req) => req.to_string(),
       Err(_) => String::from("Empty"),
   };
    
    if request_string.contains("method") {
        response_string = String::from("Method contained");
    }
    let mut response = response_string.as_bytes().as_ptr();
	//let mut io = IoHandler::new();
	//io.extend_with()
	sgx_status_t::SGX_SUCCESS
}