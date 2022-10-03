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
	pub use yasna_sgx as yasna;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	config_provider::FromFileConfigProvider,
	connection_id_generator::{ConnectionId, ConnectionIdGenerator},
	error::{WebSocketError, WebSocketResult},
	ws_server::TungsteniteWsServer,
};
use mio::{event::Evented, Token};
use std::{
	fmt::Debug,
	string::{String, ToString},
	sync::Arc,
};

pub mod certificate_generation;
pub mod config_provider;
mod connection;
pub mod connection_id_generator;
pub mod error;
mod stream_state;
mod tls_common;
pub mod ws_server;

#[cfg(any(test, feature = "mocks"))]
pub mod test;

/// Connection token alias.
#[derive(Eq, PartialEq, Clone, Copy, Debug, Hash)]
pub struct ConnectionToken(pub usize);

impl From<ConnectionToken> for Token {
	fn from(c: ConnectionToken) -> Self {
		Token(c.0)
	}
}

impl From<Token> for ConnectionToken {
	fn from(t: Token) -> Self {
		ConnectionToken(t.0)
	}
}

/// Handles a web-socket connection message.
pub trait WebSocketMessageHandler: Send + Sync {
	fn handle_message(
		&self,
		connection_token: ConnectionToken,
		message: String,
	) -> WebSocketResult<Option<String>>;
}

/// Allows to send response messages to a specific connection.
pub trait WebSocketResponder: Send + Sync {
	fn send_message(
		&self,
		connection_token: ConnectionToken,
		message: String,
	) -> WebSocketResult<()>;
}

/// Run a web-socket server with a given handler.
pub trait WebSocketServer {
	type Connection;

	fn run(&self) -> WebSocketResult<()>;

	fn is_running(&self) -> WebSocketResult<bool>;

	fn shut_down(&self) -> WebSocketResult<()>;
}

/// Abstraction of a web socket connection using mio.
pub(crate) trait WebSocketConnection: Send + Sync {
	/// Socket type, typically a TCP stream.
	type Socket: Evented;

	/// Get the underlying socket (TCP stream)
	fn socket(&self) -> Option<&Self::Socket>;

	/// Query the underlying session for readiness (read/write).
	fn get_session_readiness(&self) -> mio::Ready;

	/// Handles the ready event, the connection has work to do.
	fn on_ready(&mut self, poll: &mut mio::Poll, ev: &mio::event::Event) -> WebSocketResult<()>;

	/// True if connection was closed.
	fn is_closed(&self) -> bool;

	/// Return the connection token (= ID)
	fn token(&self) -> mio::Token;

	/// Register the connection with the mio poll.
	fn register(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		match self.socket() {
			Some(s) => {
				poll.register(
					s,
					self.token(),
					self.get_session_readiness(),
					mio::PollOpt::level() | mio::PollOpt::oneshot(),
				)?;
				Ok(())
			},
			None => Err(WebSocketError::ConnectionClosed),
		}
	}

	/// Re-register the connection with the mio poll, after handling an event.
	fn reregister(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		match self.socket() {
			Some(s) => {
				poll.reregister(
					s,
					self.token(),
					self.get_session_readiness(),
					mio::PollOpt::level() | mio::PollOpt::oneshot(),
				)?;

				Ok(())
			},
			None => Err(WebSocketError::ConnectionClosed),
		}
	}
}

pub fn create_ws_server<Handler>(
	addr_plain: &str,
	private_key: &str,
	certificate: &str,
	handler: Arc<Handler>,
) -> Arc<TungsteniteWsServer<Handler, FromFileConfigProvider>>
where
	Handler: WebSocketMessageHandler,
{
	let config_provider =
		Arc::new(FromFileConfigProvider::new(private_key.to_string(), certificate.to_string()));

	Arc::new(TungsteniteWsServer::new(addr_plain.to_string(), config_provider, handler))
}
