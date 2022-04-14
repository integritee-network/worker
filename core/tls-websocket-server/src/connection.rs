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

use crate::{error::WebSocketError, WebSocketConnection, WebSocketHandler, WebSocketResult};
use log::*;
use mio::{net::TcpStream, Token};
use rustls::{ServerSession, Session};
use std::{format, string::String, sync::Arc};
use tungstenite::{accept, Message, WebSocket};

type RustlsStream = rustls::StreamOwned<ServerSession, TcpStream>;
type RustlsWebSocket = WebSocket<RustlsStream>;

pub struct TungsteniteWsConnection<Handler> {
	web_socket: RustlsWebSocket,
	connection_token: Token,
	connection_handler: Arc<Handler>,
	is_closed: bool,
}

impl<Handler> TungsteniteWsConnection<Handler>
where
	Handler: WebSocketHandler,
{
	pub fn connect(
		tcp_stream: TcpStream,
		server_session: ServerSession,
		connection_token: Token,
		handler: Arc<Handler>,
	) -> WebSocketResult<Self> {
		let tls_stream = rustls::StreamOwned::new(server_session, tcp_stream);
		let web_socket = accept(tls_stream).map_err(|_| WebSocketError::HandShakeError)?;

		Ok(TungsteniteWsConnection {
			web_socket,
			connection_token,
			connection_handler: handler,
			is_closed: false,
		})
	}

	pub fn register(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		poll.register(
			&self.web_socket.get_ref().sock,
			self.connection_token,
			self.event_set(),
			mio::PollOpt::level() | mio::PollOpt::oneshot(),
		)?;

		Ok(())
	}

	/// What IO events we're currently waiting for,
	/// based on wants_read/wants_write.
	pub fn event_set(&self) -> mio::Ready {
		let wants_read = self.web_socket.get_ref().sess.wants_read();
		let wants_write = self.web_socket.get_ref().sess.wants_write();

		if wants_read && wants_write {
			mio::Ready::readable() | mio::Ready::writable()
		} else if wants_write {
			mio::Ready::writable()
		} else {
			mio::Ready::readable()
		}
	}

	/// We're a connection, and we have something to do.
	pub fn ready(&mut self, poll: &mut mio::Poll, ev: &mio::event::Event) -> WebSocketResult<()> {
		let mut is_closing = false;

		if ev.readiness().is_readable() {
			match self.web_socket.read_message() {
				Ok(m) =>
					if let Err(e) = self.handle_message(m) {
						error!("Failed to handle web-socket message: {:?}", e);
					},
				Err(e) => match e {
					tungstenite::Error::ConnectionClosed => is_closing = true,
					_ => error!("Failed to read message from web-socket: {:?}", e),
				},
			}
		}

		if ev.readiness().is_writable() {
			if let Err(e) = self.web_socket.write_pending() {
				match e {
					tungstenite::Error::ConnectionClosed => is_closing = true,
					_ => error!("Failed to write pending web-socket messages: {:?}", e),
				}
			}
		}

		if is_closing {
			debug!("Connection ({:?}) is closed", self.connection_token);
			self.is_closed = true;
		} else {
			// Re-register with the poll.
			self.register(poll)?;
		}
		Ok(())
	}

	fn handle_message(&mut self, message: Message) -> WebSocketResult<()> {
		if let Message::Text(string_message) = message {
			debug!("Got Message::Text on web-socket, calling handler..");
			if let Some(reply) =
				self.connection_handler.handle_message(self.connection_token, string_message)?
			{
				debug!("Handling message yielded a reply, sending it now..");
				self.write_message(reply)?;
				debug!("Reply sent successfully");
			}
			debug!("Successfully handled web-socket message");
		}
		Ok(())
	}

	fn write_message(&mut self, message: String) -> WebSocketResult<()> {
		if !self.web_socket.can_write() {
			return Err(WebSocketError::ConnectionClosed)
		}

		self.web_socket
			.write_message(Message::Text(message))
			.map_err(|e| WebSocketError::SocketWriteError(format!("{:?}", e)))
	}

	pub fn is_closed(&self) -> bool {
		self.is_closed
	}
}

impl<Handler> WebSocketConnection for TungsteniteWsConnection<Handler>
where
	Handler: WebSocketHandler,
{
	fn id(&self) -> Token {
		self.connection_token
	}

	fn read_message(&mut self) -> WebSocketResult<Message> {
		self.web_socket.read_message().map_err(|_| WebSocketError::ConnectionClosed)
	}

	fn write_pending(&mut self) -> WebSocketResult<()> {
		self.web_socket.write_pending().map_err(|_| WebSocketError::ConnectionClosed)
	}

	fn process_request<F>(&mut self, initial_call: F) -> WebSocketResult<String>
	where
		F: Fn(&str) -> String,
	{
		debug!("processing web socket request");

		let request = String::default(); //self.read_next_message()?;

		let response = (initial_call)(request.as_str());

		self.write_message(response.clone())?;

		debug!("successfully processed web socket request");
		Ok(response)
	}

	fn send_update(&mut self, message: String) -> WebSocketResult<()> {
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
