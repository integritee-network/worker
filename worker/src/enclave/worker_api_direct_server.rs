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
use std::sync::{Arc, Mutex, MutexGuard, atomic::{Ordering, AtomicPtr}};
use std::collections::HashMap;
use std::slice;
use ws::{listen, CloseCode, Handler, Message, Result, Sender, Handshake};
use std::{thread, time};
use std::sync::mpsc::channel;
use serde::{Serialize, Deserialize};
use codec::{Encode, Decode};
use core::result::Result as StdResult;
use serde_json::Value;
use sp_core::H256 as Hash;

use substratee_worker_primitives::{TransactionStatus, RpcResponse, RpcReturnValue};
use substratee_node_primitives::Request;


static WATCHED_LIST: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

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
    
    // initialize static pointer to empty HashMap
    let new_map: HashMap<Hash, WatchingClient> = HashMap::new();
    let pool_ptr = Arc::new(Mutex::new(new_map));
    let ptr = Arc::into_raw(pool_ptr);
    WATCHED_LIST.store(ptr as *mut (), Ordering::SeqCst);


}

struct WatchingClient {
    client: Sender,
    response: RpcResponse,
}

fn load_watched_list() -> Option<&'static Mutex<HashMap<Hash, WatchingClient>>>
{
    let ptr = WATCHED_LIST.load(Ordering::SeqCst) as * mut Mutex<HashMap<Hash, WatchingClient>>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &* ptr })
    }
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
    let mut result_of_rpc_response = RpcReturnValue::decode(&mut full_rpc_response.result.as_slice()).unwrap();
   // let result_of_rpc_response: EncodedReturnValue = serde_json::from_str(&full_rpc_response.result).unwrap();
    let decoded_result: StdResult<Vec<u8>,Vec<u8>> = StdResult::decode(&mut result_of_rpc_response.value.as_slice()).unwrap();


    match decoded_result.clone() {
        Ok(hash_vec) => {
            let hash = Hash::decode(&mut hash_vec.as_slice()).unwrap();
            result_of_rpc_response.value = hash.to_string().encode();
             // start watching the call with the specific hash
            if result_of_rpc_response.do_watch {
                 // Aquire lock on watched list
                let &ref mutex = load_watched_list().unwrap();
                let mut guard: MutexGuard<HashMap<Hash, WatchingClient>> = mutex.lock().unwrap();
                //let tx_pool = Arc::new(tx_pool_guard.deref());

                // create new key and value entries to store
                let new_client = WatchingClient {
                    client: req.client.clone(),
                    response: RpcResponse {
                        result: result_of_rpc_response.encode(),
                        jsonrpc: full_rpc_response.jsonrpc.clone(),
                        id: full_rpc_response.id,
                    }
                };
                guard.insert(hash.clone(), new_client); 
                
                // start watching the hash function above
               // req.client.send(decoded_response);
                //readable_response_result.do_watch = false;
               /* if TxStatus::In_block
                    readable_response_result.do_watch = false
                }*/
            }
            
        },
        Err(err_msg_vec) => {
            let err_msg = String::decode(&mut err_msg_vec.as_slice()).unwrap();
            result_of_rpc_response.value = err_msg.encode();
            result_of_rpc_response.do_watch = false;
        },
    }
    // create new return value
    let updated_rpc_response = RpcResponse {
        result: result_of_rpc_response.encode(),
        jsonrpc: full_rpc_response.jsonrpc,
        id: full_rpc_response.id,
    };

    req.client.send(serde_json::to_string(&updated_rpc_response).unwrap());
   /*  thread::sleep(ten_millis);
    req.client.send(serde_json::to_string(&updated_rpc_response).unwrap());
    req.client.send(serde_json::to_string(&updated_rpc_response).unwrap()); */

     //thread::spawn(move || {
       // let client = req.client.clone();
        /*loop {
            req.client.send(serde_json::to_string(&updated_rpc_response).unwrap());
            let ten_millis = time::Duration::from_millis(10000);
            thread::sleep(ten_millis);
        }*/
   // });
 
    // test
    //drop(req.client);
    /* if let Ok(hash_vec) = decoded_result {
        let hash = Hash::decode(&mut hash_vec.as_slice()).unwrap();
        let &ref mutex = load_watched_list().unwrap();
        let mut guard = mutex.lock().unwrap(); 

        if let Some(client_event) = guard.get_mut(&hash) {
            println!("Returned hash: {:?}", hash);
            client_event.client.send(serde_json::to_string(&updated_rpc_response).unwrap()).unwrap();
        }
    } */
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn ocall_update_status_event(
    hash_encoded: *const u8,
    hash_size: u32,
    status_update_encoded: *const u8,
    status_size: u32,
) -> sgx_status_t {
    let mut status_update_slice = slice::from_raw_parts(status_update_encoded, status_size as usize);
    let status_update: TransactionStatus = Decode::decode(&mut status_update_slice).unwrap();
    let mut hash_slice = slice::from_raw_parts(hash_encoded, hash_size as usize);
    if let Ok(hash) = Hash::decode(&mut hash_slice) {       
        // Aquire watched list lock
        let &ref mutex = load_watched_list().unwrap();
        let mut guard = mutex.lock().unwrap();  
         if let Some(client_event) = guard.get_mut(&hash) {
            //println!("Returned hash: {:?}", hash);
            let mut event = &mut client_event.response;
            // Aquire result of old RpcResponse
            let old_result: Vec<u8> = event.result.clone();
            let mut result = RpcReturnValue::decode(&mut old_result.as_slice()).unwrap();
            
            // update status
            result.status = status_update;
            

            match result.status {
                TransactionStatus::Invalid => result.do_watch = false,
                _ => result.do_watch = true,
            };
            event.result = result.encode();
            client_event.client.send(serde_json::to_string(&event).unwrap());             

        } 
    } 
   
    sgx_status_t::SGX_SUCCESS
}