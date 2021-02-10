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

use codec::{Decode, Encode};
use log::*;
use sp_core::H256 as Hash;
use std::collections::HashMap;
use std::slice;
use std::sync::{
    atomic::{AtomicPtr, Ordering},
    Arc, Mutex, MutexGuard,
};
use std::thread;
use ws::{listen, CloseCode, Handler, Message, Result, Sender};

use substratee_worker_primitives::{RpcResponse, RpcReturnValue, TrustedOperationStatus, DirectCallStatus};

static WATCHED_LIST: AtomicPtr<()> = AtomicPtr::new(0 as *mut ());
static EID: AtomicPtr<u64> = AtomicPtr::new(0 as *mut sgx_enclave_id_t);

extern "C" {
    fn initialize_pool(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

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
    eid: sgx_enclave_id_t,
) {
    // Server WebSocket handler
    struct Server {
        client: Sender,
    }  

    // initialize static pointer to eid
    let eid_ptr = Arc::into_raw(Arc::new(eid));
    EID.store(eid_ptr as *mut sgx_enclave_id_t, Ordering::SeqCst);

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            let request = DirectWsServerRequest::new(
                self.client.clone(),
                msg.to_string(),
            );
            if let Err(_) = handle_direct_invocation_request(request) {
                error!("direct invocation call was not successful");
            }
            Ok(())
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            debug!(
                "Direct invocation WebSocket closing for ({:?}) {}",
                code, reason
            );
        }
    }
    // Server thread
    info!("Starting direct invocation WebSocket server on {}", addr);
    thread::spawn(move || {
        match listen(addr.clone(), |out| Server {
            client: out,
        }) {
            Ok(_) => (),
            Err(e) => {
                error!(
                    "error starting worker direct invocation api server on {}: {}",
                    addr, e
                );
            }
        };
    });

    // initialise top pool in enclave
    thread::spawn(move || {
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let result = unsafe { initialize_pool(eid, &mut retval) };

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

fn load_watched_list() -> Option<&'static Mutex<HashMap<Hash, WatchingClient>>> {
    let ptr = WATCHED_LIST.load(Ordering::SeqCst) as *mut Mutex<HashMap<Hash, WatchingClient>>;
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

pub fn handle_direct_invocation_request(
    req: DirectWsServerRequest,
) -> Result<()> {
    info!("Got message '{:?}'. ", req.request);
    let eid = unsafe{ *EID.load(Ordering::SeqCst)};
    // forwarding rpc string directly to enclave
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let response_len = 8192;
    let mut response: Vec<u8> = vec![0u8; response_len as usize];

    let msg: Vec<u8> = req.request.as_bytes().to_vec();

    let result = unsafe {
        call_rpc_methods(
            eid,
            &mut retval,
            msg.as_ptr(),
            msg.len() as u32,
            response.as_mut_ptr(),
            response_len,
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {
            debug!("[RPC-Call] ECALL success!");
        }
        _ => {
            error!("[RPC-call] ECALL Enclave Failed {}!", result.as_str());
        }
    }
    let decoded_response = String::from_utf8_lossy(&response).to_string();
    let full_rpc_response: RpcResponse = serde_json::from_str(&decoded_response).unwrap();
    let result_of_rpc_response =
        RpcReturnValue::decode(&mut full_rpc_response.result.as_slice()).unwrap();
    match result_of_rpc_response.status {
        DirectCallStatus::TrustedOperationStatus(_) => {             
            if result_of_rpc_response.do_watch {
                // start watching the call with the specific hash
                if let Ok(hash) = Hash::decode(&mut result_of_rpc_response.value.as_slice()) {
                    // Aquire lock on watched list
                    let mutex = load_watched_list().unwrap();
                    let mut watch_list: MutexGuard<HashMap<Hash, WatchingClient>> = mutex.lock().unwrap();
                    
                    // create new key and value entries to store
                    let new_client = WatchingClient {
                        client: req.client.clone(),
                        response: RpcResponse {
                            result: result_of_rpc_response.encode(),
                            jsonrpc: full_rpc_response.jsonrpc.clone(),
                            id: full_rpc_response.id,
                        },
                    };
                    // save in watch list
                    watch_list.insert(hash, new_client);
                }
            }
        },
        // Simple return value, no need of further server actions
        _ => { },
    }
    req.client
        .send(serde_json::to_string(&full_rpc_response).unwrap())    
}

#[no_mangle]
pub unsafe extern "C" fn ocall_update_status_event(
    hash_encoded: *const u8,
    hash_size: u32,
    status_update_encoded: *const u8,
    status_size: u32,
) -> sgx_status_t {
    let mut status_update_slice =
        slice::from_raw_parts(status_update_encoded, status_size as usize);
    let status_update = TrustedOperationStatus::decode(&mut status_update_slice).unwrap();
    let mut hash_slice = slice::from_raw_parts(hash_encoded, hash_size as usize);
    if let Ok(hash) = Hash::decode(&mut hash_slice) {
        // Aquire watched list lock
        let mutex = load_watched_list().unwrap();
        let mut watch_list = mutex.lock().unwrap();
        let mut continue_watching = true;
        if let Some(client_event) = watch_list.get_mut(&hash) {
            let mut event = &mut client_event.response;
            // Aquire result of old RpcResponse
            let old_result: Vec<u8> = event.result.clone();
            let mut result = RpcReturnValue::decode(&mut old_result.as_slice()).unwrap();

            match status_update {
                TrustedOperationStatus::Invalid
                | TrustedOperationStatus::InBlock
                | TrustedOperationStatus::Finalized
                | TrustedOperationStatus::Usurped => {
                    // Stop watching
                    result.do_watch = false;
                    continue_watching = false;
                }
                _ => {}
            };
            // update response
            result.status = DirectCallStatus::TrustedOperationStatus(status_update);
            event.result = result.encode();
            client_event
                .client
                .send(serde_json::to_string(&event).unwrap())
                .unwrap();

            if !continue_watching {
                client_event.client.close(CloseCode::Normal).unwrap();
            }
        } else {
            continue_watching = false;
        }
        if !continue_watching {
            watch_list.remove(&hash);
        }
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ocall_send_status(
    hash_encoded: *const u8,
    hash_size: u32,
    status_encoded: *const u8,
    status_size: u32,
) -> sgx_status_t {
    let status_slice =
        slice::from_raw_parts(status_encoded, status_size as usize);  
    let mut hash_slice = slice::from_raw_parts(hash_encoded, hash_size as usize);
    if let Ok(hash) = Hash::decode(&mut hash_slice) {
        // Aquire watched list lock
        let mutex = load_watched_list().unwrap();
        let mut guard = mutex.lock().unwrap();
        if let Some(client_response) = guard.get_mut(&hash) {
            let mut response = &mut client_response.response;
        
            // create return value
            let result = RpcReturnValue {
                value: status_slice.to_vec(),
                do_watch: false,
                status: DirectCallStatus::TrustedOperationStatus(TrustedOperationStatus::Submitted),
            };

            // update response
            response.result = result.encode();
            client_response
                .client
                .send(serde_json::to_string(&response).unwrap())
                .unwrap();
        
            client_response.client.close(CloseCode::Normal).unwrap();

        } 
        guard.remove(&hash);
    }

    sgx_status_t::SGX_SUCCESS
}
