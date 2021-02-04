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
use std::thread;
use std::sync::mpsc::channel;
use serde::{Serialize, Deserialize};
use codec::Decode;
use core::result::Result as StdResult;
use serde_json::Value;

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
    let new_map: HashMap<String, WatchingClient> = HashMap::new();
    let pool_ptr = Arc::new(Mutex::new(new_map));
    let ptr = Arc::into_raw(pool_ptr);
    WATCHED_LIST.store(ptr as *mut (), Ordering::SeqCst);


}

struct WatchingClient {
    client: Sender,
    response: RpcResponse,
}

// TODO: double specified in enclace & worker
#[derive(Serialize, Deserialize)]
struct EncodedReturnValue {
    value: Vec<u8>,
    do_watch: bool,
    status: TransactionStatus,
}

// TODO: double specified in enclace & worker
#[derive(Serialize, Deserialize)]
struct DecodedReturnValue {
    value: String,
    do_watch: bool,
    status: TransactionStatus
}

// TODO: Nehmen aus enclave.. oder sonst iwi
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Decode)]
pub enum TransactionStatus {
	/// Transaction is part of the future queue.
	Future,
	/// Transaction is part of the ready queue.
	Ready,
	/// The transaction has been broadcast to the given peers.
	Broadcast,
	/// Transaction has been included in block with given hash.
	InBlock,
	/// The block this transaction was included in has been retracted.
	Retracted,
	/// Maximum number of finality watchers has been reached,
	/// old watchers are being removed.
	FinalityTimeout,
	/// Transaction has been finalized by a finality-gadget, e.g GRANDPA
	Finalized,
	/// Transaction has been replaced in the pool, by another transaction
	/// that provides the same tags. (e.g. same (sender, nonce)).
	Usurped,
	/// Transaction has been dropped from the pool because of the limit.
	Dropped,
	/// Transaction is no longer valid in the current state.
	Invalid,
}

#[derive(Serialize, Deserialize)]
struct RpcResponse {
    jsonrpc: String,
    result: String,
    id: u32,
}


fn load_watched_list() -> Option<&'static Mutex<HashMap<String, WatchingClient>>>
{
    let ptr = WATCHED_LIST.load(Ordering::SeqCst) as * mut Mutex<HashMap<String, WatchingClient>>;
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
    let result_of_rpc_response: EncodedReturnValue = serde_json::from_str(&full_rpc_response.result).unwrap();
    let decoded_result: StdResult<Vec<u8>,Vec<u8>> = StdResult::decode(&mut result_of_rpc_response.value.as_slice()).unwrap();

    let mut readable_response_result = DecodedReturnValue{
        do_watch: result_of_rpc_response.do_watch,
        value: "".to_owned(),
        status: TransactionStatus::Invalid,
    };
    match decoded_result {
        Ok(hash_vec) => {
            let hash = String::decode(&mut hash_vec.as_slice()).unwrap();
            // overwrite encoded non-readable return value to send to the client
            readable_response_result.value = hash.clone();

             // start watching the call with the specific hash
            if result_of_rpc_response.do_watch {
                // Aquire lock on watched list
                let &ref mutex = load_watched_list().unwrap();
                let mut guard: MutexGuard<HashMap<String, WatchingClient>> = mutex.lock().unwrap();
                //let tx_pool = Arc::new(tx_pool_guard.deref());

                // create new key and value entries to store
                let new_client = WatchingClient {
                    client: req.client.clone(),
                    response: RpcResponse {
                        result: serde_json::to_string(&readable_response_result).unwrap(),
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

#[no_mangle]
pub unsafe extern "C" fn ocall_update_status_event(
    hash_encoded: *const u8,
    hash_size: u32,
    status_update_encoded: *const u8,
    status_size: u32,
    //response: *mut u8,
    //resp_size: u32,
) -> sgx_status_t {
    let mut hash_slice = slice::from_raw_parts(hash_encoded, hash_size as usize);
    let hash: String = Decode::decode(&mut hash_slice).unwrap();
    let mut status_update_slice = slice::from_raw_parts(status_update_encoded, status_size as usize);
    let status_update: TransactionStatus = Decode::decode(&mut status_update_slice).unwrap();

    // Aquire watched list lock
    let &ref mutex = load_watched_list().unwrap();
    let mut guard: MutexGuard<HashMap<String, WatchingClient>> = mutex.lock().unwrap();  
    if let Some(client_event) = guard.get_mut(&hash) { 
        let mut event = &mut client_event.response;
        // Aquire result of old RpcResponse
        let old_result: &str = &event.result;
        let mut result: DecodedReturnValue = serde_json::from_str(old_result).unwrap();
        // update status
        result.status = status_update;
        let new_result: String = serde_json::to_string(&result).unwrap();
        event.result = new_result;

        client_event.client.send(serde_json::to_string(&event).unwrap());
    }


    /*
    
    let resp_slice = slice::from_raw_parts_mut(response, resp_size as usize);

    let api = Api::<sr25519::Pair>::new(NODE_URL.lock().unwrap().clone());

    let requests: Vec<WorkerRequest> = Decode::decode(&mut req_slice).unwrap();

    let resp: Vec<WorkerResponse<Vec<u8>>> = requests
        .into_iter()
        .map(|req| match req {
            //let res =
            WorkerRequest::ChainStorage(key, hash) => WorkerResponse::ChainStorage(
                key.clone(),
                api.get_opaque_storage_by_key_hash(StorageKey(key.clone()), hash),
                api.get_storage_proof_by_keys(vec![StorageKey(key)], hash)
                    .map(|read_proof| read_proof.proof.into_iter().map(|bytes| bytes.0).collect()),
            ),
        })
        .collect();

    write_slice_and_whitespace_pad(resp_slice, resp.encode());*/
    sgx_status_t::SGX_SUCCESS
}