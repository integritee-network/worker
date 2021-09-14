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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{WebSocketConnection, WebSocketError, WebSocketResult};
use log::*;
use rustls::ServerSession;
use std::{
	format,
	net::TcpStream,
	string::{String, ToString},
};
use tungstenite::{accept, Message, WebSocket};

type RustlsStream = rustls::StreamOwned<ServerSession, TcpStream>;
type RustlsWebSocket = WebSocket<RustlsStream>;

pub struct TungsteniteWsConnection {
	web_socket: RustlsWebSocket,
}

impl TungsteniteWsConnection {
	pub fn connect(
		tcp_stream: TcpStream,
		server_session: ServerSession,
	) -> WebSocketResult<TungsteniteWsConnection> {
		let tls_stream = rustls::StreamOwned::new(server_session, tcp_stream);
		let web_socket = accept(tls_stream).map_err(|_| WebSocketError::HandShakeError)?;

		Ok(TungsteniteWsConnection { web_socket })
	}

	fn read_next_message(&mut self) -> WebSocketResult<String> {
		// loop until we have a Message::Text
		loop {
			let message =
				self.web_socket.read_message().map_err(|_| WebSocketError::ConnectionClosed)?;
			if let Message::Text(s) = message {
				return Ok(s)
			}
		}
	}

	fn write_message(&mut self, message: &str) -> WebSocketResult<()> {
		if !self.web_socket.can_write() {
			return Err(WebSocketError::ConnectionClosed)
		}

		self.web_socket
			.write_message(Message::Text(message.to_string()))
			.map_err(|e| WebSocketError::SocketWriteError(format!("{:?}", e)))
	}
}

impl WebSocketConnection for TungsteniteWsConnection {
	fn process_request<F>(&mut self, initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String,
	{
		debug!("processing web socket request");

		let request = self.read_next_message()?;

		let response = (initial_call)(request.as_str());

		self.write_message(response.as_str())?;

		debug!("successfully processed web socket request");
		Ok(response)
	}

	fn send_update(&mut self, message: &str) -> WebSocketResult<()> {
		debug!("sending web socket update");
		self.write_message(message)
	}

	fn close(&mut self) {
		match self.web_socket.close(None) {
			Ok(()) => {
				debug!("web socket connection closed");
			},
			Err(e) => {
				error!("failed to close web socket connection (already closed?): {:?}", e);
			},
		}

		match self.web_socket.write_pending() {
			Ok(()) => {
				debug!("write_pending succeeded");
			},
			Err(e) => {
				// a closed error is to be expected here (according to '.close()' documentation
				debug!("flushed connection after closing, received error information: {:?}", e);
			},
		}
	}
}
