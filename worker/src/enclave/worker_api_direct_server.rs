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
use sgx_types::*;

use log::*;
use std::sync::mpsc::Sender as MpscSender;
use ws::{listen, CloseCode, Handler, Message, Result, Sender, Handshake};
use std::thread;
use std::sync::mpsc::channel;
use serde::{Serialize, Deserialize};
use codec::Decode;
use core::result::Result as StdResult;
use serde_json::Value;

extern "C" {
	fn initialize_pool(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
    ) -> sgx_status_t;

    fn call_rpc_methods(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
		request: *const u8,
		request_len: u32,
		response: *mut u8,
		response_len: u32,
	) -> sgx_status_t;		
}

#[derive(Clone, Debug)]
pub struct DirectWsServerRequest {
    client: Sender,
    request: String,
}

impl DirectWsServerRequest {
    pub fn new(client: Sender, request: String) -> Self {
        Self { client, request }
    }
}

pub fn start_worker_api_direct_server(
    addr: String,
    worker: MpscSender<DirectWsServerRequest>, 
    eid: sgx_enclave_id_t) {
    // Server WebSocket handler
    struct Server {
        client: Sender,
        worker: MpscSender<DirectWsServerRequest>,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            debug!("Forwarding message to worker api direct event loop: {:?}", msg);            
            self.worker.send(DirectWsServerRequest::new(self.client.clone(), msg.to_string()))
                        .unwrap();
            Ok(())
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            debug!("Direct invocation WebSocket closing for ({:?}) {}", code, reason);
        }
    }
    // Server thread
    info!("Starting direct invocation WebSocket server on {}", addr);
    thread::spawn(move || {
        match listen(addr.clone(), |out| Server {
            client: out,
            worker: worker.clone(),
        }) {
            Ok(_) => (),
            Err(e) => {
                error!("error starting worker direct invocation api server on {}: {}", addr, e);
            }
        };
	});
	
	// initialise tx pool in enclave	
	thread::spawn(move || {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let result = unsafe {
            initialize_pool(eid, &mut retval)
        };
    
        match result {
            sgx_status_t::SGX_SUCCESS => {
                debug!("[TX-pool init] ECALL success!");
            }
            _ => {
                error!("[TX-pool init] ECALL Enclave Failed {}!", result.as_str());
            }
        }
	});
}

// TODO: double specified in enclace & worker
#[derive(Serialize, Deserialize)]
struct EncodedReturnValue {
    value: Vec<u8>,
    do_watch: bool,
}

// TODO: double specified in enclace & worker
#[derive(Serialize, Deserialize)]
struct DecodedReturnValue {
    value: String,
    do_watch: bool,
}

#[derive(Serialize, Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    result: String,
    id: u32,
}

pub fn handle_direct_invocation_request(
	req: DirectWsServerRequest,
    eid: sgx_enclave_id_t,
) -> Result<()> {
    info!("Got message '{:?}'. ", req.request);
    // forwarding rpc string directly to enclave
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let response_len = 8192;
	let mut response: Vec<u8> = vec![0u8; response_len as usize];

	let msg: Vec<u8> = req.request.as_bytes().to_vec();


    let result = unsafe {
        call_rpc_methods(eid, &mut retval, msg.as_ptr(), msg.len() as u32, response.as_mut_ptr(), response_len)
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
			debug!("[RPC-Call] ECALL success!");
        }
        _ => {
			error!("[RPC-call] ECALL Enclave Failed {}!", result.as_str());
        }
    }
    // of type: {"jsonrpc":"2.0","result":"{\"value\":[..],\"do_watch\":true}","id":1} 
    let decoded_response: String = String::from_utf8_lossy(&response).to_string();
    let full_rpc_response: RpcResponse = serde_json::from_str(&decoded_response).unwrap();
    let result_of_rpc_response: EncodedReturnValue = serde_json::from_str(&full_rpc_response.result).unwrap();
    let decoded_result: StdResult<Vec<u8>,Vec<u8>> = StdResult::decode(&mut result_of_rpc_response.value.as_slice()).unwrap();

    let mut readable_response_result = DecodedReturnValue{
        do_watch: result_of_rpc_response.do_watch,
        value: "".to_owned(),
    };
    match decoded_result {
        Ok(hash_vec) => {
            let hash = String::decode(&mut hash_vec.as_slice()).unwrap();
             // start watching the call with the specific hash
            if result_of_rpc_response.do_watch{
                // start watching the hash function above
            }
            // overwrite encoded non-readable return value to send to the client
            readable_response_result.value = hash;
        },
        Err(err_msg_vec) => {
            let err_msg = String::decode(&mut err_msg_vec.as_slice()).unwrap();
            readable_response_result.value = err_msg;
            readable_response_result.do_watch = false;
        },
    }
    // create new return value
    let updated_rpc_response = RpcResponse {
        result: serde_json::to_string(&readable_response_result).unwrap(),
        jsonrpc: full_rpc_response.jsonrpc,
        id: full_rpc_response.id,
    };

	req.client.send(serde_json::to_string(&updated_rpc_response).unwrap())
}
