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
use lazy_static::lazy_static;
use log::*;
use parking_lot::RwLock;
use std::net::SocketAddr;
use warp::Filter;

lazy_static! {
	static ref INITIALIZED_HANDLE: RwLock<bool> = RwLock::new(false);
}

pub async fn start_is_initialized_server(port: u16) -> ServiceResult<()> {
	let is_initialized_route = warp::path!("is_initialized").and_then(|| async move {
		if *INITIALIZED_HANDLE.read() {
			Ok("I am initialized.")
		} else {
			Err(warp::reject::not_found())
		}
	});

	let socket_addr: SocketAddr = ([0, 0, 0, 0], port).into();

	info!("Running initialized server on: {:?}", socket_addr);
	warp::serve(is_initialized_route).run(socket_addr).await;

	info!("Initialized server shut down");
	Ok(())
}

/// Set initialized handler value to true.
pub fn set_initialized() {
	let mut initialized_lock = INITIALIZED_HANDLE.write();
	*initialized_lock = true;
}
