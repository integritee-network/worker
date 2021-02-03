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
	let response_string: String = String::from_utf8(response).expect("Found invalid UTF-8");
	req.client.send(response_string)
}
