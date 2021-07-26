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
use std::{sync::Arc, thread, thread::JoinHandle};
use substratee_enclave_api::direct_request::DirectRequest;
use ws::{listen, Handler};

/// Trait for a WebSocket Server for direct invocation
pub trait RunWsServer {
	fn run(&self, addr: String);
}

pub struct WsDirectServerRunner<H, HF, E>
where
	H: Handler,
	HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
	E: DirectRequest,
{
	handler_factory: Arc<HF>,
	enclave_api: Arc<E>,
}

impl<H, HF, E> RunWsServer for WsDirectServerRunner<H, HF, E>
where
	H: Handler,
	HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
	E: DirectRequest,
{
	fn run(&self, addr: String) {
		let init_top_pool_handle = self.init_top_pool();

		self.spawn_handler_thread(addr);

		// ensure top pool is initialised before returning
		init_top_pool_handle.join().unwrap();
		println!("Successfully initialised top pool");
	}
}

impl<H, HF, E> WsDirectServerRunner<H, HF, E>
where
	H: Handler,
	HF: CreateWsHandler<Handler = H> + Sync + Send + 'static,
	E: DirectRequest,
{
	pub fn new(handler_factory: Arc<HF>, enclave_api: Arc<E>) -> Self {
		WsDirectServerRunner { handler_factory, enclave_api }
	}

	fn init_top_pool(&self) -> JoinHandle<()> {
		// initialize top pool in enclave
		let enclave_api = self.enclave_api.clone();

		thread::spawn(move || {
			let result = enclave_api.initialize_pool();

			match result {
				Ok(_) => {
					debug!("[TX-pool init] ECALL success!");
				},
				Err(e) => {
					error!("[TX-pool init] ECALL Enclave Failed {:?}!", e);
				},
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
					error!("error starting worker direct invocation api server on {}: {}", addr, e);
				},
			};
		});
	}
}
