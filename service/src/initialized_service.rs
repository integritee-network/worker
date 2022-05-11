/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

//! Service to determine if the integritee services is initialized and registered on the node,
//! hosted on a http server.

use crate::error::ServiceResult;
use log::*;
use parking_lot::RwLock;
use std::{net::SocketAddr, sync::Arc};
use warp::Filter;

pub async fn start_is_initialized_server<Handler>(
	initialization_handler: Arc<Handler>,
	port: u16,
) -> ServiceResult<()>
where
	Handler: IsInitialized + Send + Sync + 'static,
{
	let is_initialized_route = warp::path!("is_initialized").and_then(move || {
		let handler_clone = initialization_handler.clone();
		async move {
			if handler_clone.is_initialized() {
				Ok("I am initialized.")
			} else {
				Err(warp::reject::not_found())
			}
		}
	});

	let socket_addr: SocketAddr = ([0, 0, 0, 0], port).into();

	info!("Running initialized server on: {:?}", socket_addr);
	warp::serve(is_initialized_route).run(socket_addr).await;

	info!("Initialized server shut down");
	Ok(())
}

/// Trait to query of a worker is considered fully initialized.
pub trait IsInitialized {
	fn is_initialized(&self) -> bool;
}

/// Tracker for initialization. Used by components that ensure these steps were taken.
pub trait TrackInitialization {
	fn registered_on_parentchain(&self);

	fn sidechain_block_produced(&self);

	fn worker_for_shard_registered(&self);
}

#[derive(Default)]
pub struct InitializationHandler {
	registered_on_parentchain: RwLock<bool>,
	sidechain_block_produced: RwLock<bool>,
	worker_for_shard_registered: RwLock<bool>,
}

impl TrackInitialization for InitializationHandler {
	fn registered_on_parentchain(&self) {
		let mut registered_lock = self.registered_on_parentchain.write();
		*registered_lock = true;
	}

	fn sidechain_block_produced(&self) {
		let mut block_produced_lock = self.sidechain_block_produced.write();
		*block_produced_lock = true;
	}

	fn worker_for_shard_registered(&self) {
		let mut registered_lock = self.worker_for_shard_registered.write();
		*registered_lock = true;
	}
}

impl IsInitialized for InitializationHandler {
	fn is_initialized(&self) -> bool {
		*self.registered_on_parentchain.read()
			&& *self.worker_for_shard_registered.read()
			&& *self.sidechain_block_produced.read()
	}
}
