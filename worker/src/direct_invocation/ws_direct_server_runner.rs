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

use crate::direct_invocation::ws_handler::CreateWsHandler;
use log::*;
use sgx_types::{sgx_enclave_id_t, sgx_status_t};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use ws::{listen, Handler};

// TODO replace these extern C e-calls with a EnclaveAPI member field in the server impl
extern "C" {
    fn initialize_pool(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

/// Trait for a WebSocket Server for direct invocation
pub trait RunWsServer {
    fn run(&self, addr: String);
}

pub struct WsDirectServerRunner<H, HF>
where
    H: Handler,
    HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
{
    handler_factory: Arc<HF>,
    enclave_id: sgx_enclave_id_t,
}

impl<H, HF> RunWsServer for WsDirectServerRunner<H, HF>
where
    H: Handler,
    HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
{
    fn run(&self, addr: String) {
        let init_top_pool_handle = self.init_top_pool();

        self.spawn_handler_thread(addr);

        // ensure top pool is initialised before returning
        init_top_pool_handle.join().unwrap();
        println!("Successfully initialised top pool");
    }
}

impl<H, HF> WsDirectServerRunner<H, HF>
where
    H: Handler,
    HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
{
    pub fn new(handler_factory: Arc<HF>, enclave_id: sgx_enclave_id_t) -> Self {
        WsDirectServerRunner {
            handler_factory,
            enclave_id,
        }
    }

    fn init_top_pool(&self) -> JoinHandle<()> {
        // initialise top pool in enclave
        let enclave_id = self.enclave_id;

        thread::spawn(move || {
            let mut retval = sgx_status_t::SGX_SUCCESS;
            let result = unsafe { initialize_pool(enclave_id, &mut retval) };

            match result {
                sgx_status_t::SGX_SUCCESS => {
                    debug!("[TX-pool init] ECALL success!");
                }
                _ => {
                    error!("[TX-pool init] ECALL Enclave Failed {}!", result.as_str());
                }
            }
        })
    }

    fn spawn_handler_thread(&self, addr: String) {
        info!("Starting direct invocation WebSocket server on {}", addr);
        let handler_factory = self.handler_factory.clone();

        thread::spawn(move || {
            match listen(addr.clone(), |out| handler_factory.create(out)) {
                Ok(_) => (),
                Err(e) => {
                    error!(
                        "error starting worker direct invocation api server on {}: {}",
                        addr, e
                    );
                }
            };
        });
    }
}
