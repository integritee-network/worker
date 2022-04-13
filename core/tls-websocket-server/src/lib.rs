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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use mio_sgx as mio;
	pub use rustls_sgx as rustls;
	pub use thiserror_sgx as thiserror;
	pub use tungstenite_sgx as tungstenite;
	pub use webpki_sgx as webpki;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	connection::TungsteniteWsConnection,
	connection_id_generator::{ConnectionId, ConnectionIdGenerator},
	error::WebSocketResult,
	ws_server::TungsteniteWsServer,
};
use log::*;
use std::{
	string::{String, ToString},
	sync::Arc,
};

mod common;
pub mod connection;
pub mod connection_id_generator;
pub mod connection_repository;
pub mod error;
mod ws_server;

#[cfg(test)]
mod test;

/// Abstraction of a web socket connection.
pub trait WebSocketConnection: Send + Sync {
	fn id(&self) -> ConnectionId;

	fn process_request<F>(&mut self, initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String;

	fn send_update(&mut self, message: &str) -> WebSocketResult<()>;

	fn close(&mut self);
}

/// Handles a web-socket connection
pub trait WebSocketHandler {
	type Connection: WebSocketConnection;

	fn handle(&self, connection: Self::Connection) -> WebSocketResult<()>;
}

/// Run a web-socket server with a given handler
pub trait WebSocketServer {
	type Connection;

	fn run<Handler>(&self, handler: Arc<Handler>) -> WebSocketResult<()>
	where
		Handler: WebSocketHandler<Connection = Self::Connection>;
}

pub fn run_ws_server<Handler>(addr_plain: &str, handler: Arc<Handler>)
where
	Handler: WebSocketHandler<Connection = TungsteniteWsConnection>,
{
	let cert = "end.fullchain".to_string();
	let key = "end.rsa".to_string();

	let id_generator = Arc::new(ConnectionIdGenerator::default());
	let web_socket_server =
		TungsteniteWsServer::new(addr_plain.to_string(), cert, key, id_generator);

	match web_socket_server.run(handler) {
		Ok(()) => {},
		Err(e) => {
			error!("Web socket server encountered an unexpected error: {:?}", e)
		},
	}
}
