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
// Because we need mio channel, but mio-extras is not ported to SGX!
#![allow(deprecated)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

extern crate core;
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
	config_provider::FromFileConfigProvider,
	connection_id_generator::{ConnectionId, ConnectionIdGenerator},
	error::WebSocketResult,
	ws_server::TungsteniteWsServer,
};
use log::*;
use mio::{Evented, Token};
use std::{
	string::{String, ToString},
	sync::Arc,
};

mod config_provider;
pub mod connection;
pub mod connection_id_generator;
pub mod error;
mod tls_common;
mod ws_server;

#[cfg(test)]
mod test;

/// Handles a web-socket connection message.
pub trait WebSocketMessageHandler: Send + Sync {
	fn handle_message(
		&self,
		connection_token: Token,
		message: String,
	) -> WebSocketResult<Option<String>>;
}

/// Allows to send response messages to a specific connection.
pub trait WebSocketResponder: Send + Sync {
	fn send_message(&self, connection_token: Token, message: String) -> WebSocketResult<()>;
}

/// Run a web-socket server with a given handler.
pub trait WebSocketServer {
	type Connection;

	fn run(&self) -> WebSocketResult<()>;

	fn shut_down(&self) -> WebSocketResult<()>;
}

/// Abstraction of a web socket connection using mio.
pub(crate) trait WebSocketConnection: Send + Sync {
	/// Socket type, typically a TCP stream.
	type Socket: Evented;

	/// Get the underlying socket (TCP stream)
	fn socket(&self) -> &Self::Socket;

	/// What IO events we're currently waiting for,
	/// based on wants_read/wants_write.
	fn event_set(&self) -> mio::Ready;

	/// Ready event, connection has work to do.
	fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::event::Event) -> WebSocketResult<()>;

	/// True if connection was closed.
	fn is_closed(&self) -> bool;

	/// Return the connection token (= ID)
	fn token(&self) -> mio::Token;

	/// Register the connection with the mio poll.
	fn register(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		poll.register(
			self.socket(),
			self.token(),
			self.event_set(),
			mio::PollOpt::level() | mio::PollOpt::oneshot(),
		)?;

		Ok(())
	}

	/// Re-register the connection with the mio poll, after handling an event.
	fn reregister(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		poll.reregister(
			self.socket(),
			self.token(),
			self.event_set(),
			mio::PollOpt::level() | mio::PollOpt::oneshot(),
		)?;

		Ok(())
	}
}

pub fn run_ws_server<Handler>(addr_plain: &str, handler: Arc<Handler>)
where
	Handler: WebSocketMessageHandler,
{
	let config_provider =
		Arc::new(FromFileConfigProvider::new("end.rsa".to_string(), "end.fullchain".to_string()));
	let web_socket_server =
		TungsteniteWsServer::new(addr_plain.to_string(), config_provider, handler);

	match web_socket_server.run() {
		Ok(()) => {},
		Err(e) => {
			error!("Web socket server encountered an unexpected error: {:?}", e)
		},
	}
}
