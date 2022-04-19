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
use core::str::from_utf8;

use crate::{error::WebSocketError, WebSocketConnection, WebSocketHandler, WebSocketResult};
use log::*;
use mio::{net::TcpStream, Token};
use rustls::{ServerSession, Session};
use std::{format, string::String, sync::Arc};
use tungstenite::{
	accept, handshake::server::NoCallback, protocol::Role, Message, ServerHandshake, WebSocket,
};

type RustlsStream = rustls::StreamOwned<ServerSession, TcpStream>;
type RustlsWebSocket = WebSocket<RustlsStream>;

pub struct TungsteniteWsConnection<Handler> {
	tls_stream: Option<RustlsStream>,
	web_socket: Option<RustlsWebSocket>,
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
		// let tls_stream = rustls::StreamOwned::new(server_session, tcp_stream);
		// let web_socket =
		// 	accept(tls_stream).map_err(|e| WebSocketError::HandShakeError(format!("{:?}", e)))?;

		Ok(TungsteniteWsConnection {
			tls_stream: Some(rustls::StreamOwned::new(server_session, tcp_stream)),
			web_socket: None,
			connection_token,
			connection_handler: handler,
			is_closed: false,
		})
	}

	pub fn register(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		let socket = self.get_active_stream();

		poll.register(
			&socket.sock,
			self.connection_token,
			self.event_set(),
			mio::PollOpt::level() | mio::PollOpt::oneshot(),
		)?;

		Ok(())
	}

	fn reregister(&mut self, poll: &mio::Poll) -> WebSocketResult<()> {
		let socket = self.get_active_stream();

		poll.reregister(
			&socket.sock,
			self.connection_token,
			self.event_set(),
			mio::PollOpt::level() | mio::PollOpt::oneshot(),
		)?;

		Ok(())
	}

	fn get_active_stream(&self) -> &RustlsStream {
		match &self.web_socket {
			Some(w) => w.get_ref(),
			None => self.tls_stream.as_ref().expect("At least one tls stream object to be active"),
		}
	}

	fn get_active_stream_mut(&mut self) -> &mut RustlsStream {
		match &mut self.web_socket {
			Some(w) => w.get_mut(),
			None => self.tls_stream.as_mut().expect("At least one tls stream object to be active"),
		}
	}

	/// What IO events we're currently waiting for,
	/// based on wants_read/wants_write.
	pub fn event_set(&self) -> mio::Ready {
		let active_stream = self.get_active_stream();
		let wants_read = active_stream.sess.wants_read();
		let wants_write = active_stream.sess.wants_write();

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
			debug!("Connection ({:?}) is readable", self.connection_token);

			let continue_websocket = match self.do_tls_read() {
				ConnectionState::Closing => {
					is_closing = true;
					false
				},
				ConnectionState::Blocked => false,
				ConnectionState::Alive => true,
				ConnectionState::TlsHandshake => false,
			};

			debug!("Is TLS handshaking: {}", self.get_active_stream_mut().sess.is_handshaking());

			if continue_websocket {
				// // Read and process all available plaintext.
				// let mut buf = Vec::new();
				//
				// use std::io::Read;
				// match self.get_active_stream_mut().sess.read_to_end(&mut buf) {
				// 	Ok(_) => {
				// 		debug!("Read plaintext: {:?}", String::from_utf8(buf));
				// 	},
				// 	Err(e) =>
				// 		return Err(WebSocketError::Other(
				// 			format!("TLS session read failed: {:?}", e).into(),
				// 		)),
				// }
				is_closing = self.read_or_initialize_websocket()?;
			}
		}

		if ev.readiness().is_writable() {
			debug!("Connection ({:?}) is writable", self.connection_token);

			let continue_websocket = match self.do_tls_write() {
				ConnectionState::Closing => {
					is_closing = true;
					false
				},
				ConnectionState::Blocked => false,
				ConnectionState::Alive => true,
				ConnectionState::TlsHandshake => false,
			};

			if continue_websocket {
				if let Some(web_socket) = self.web_socket.as_mut() {
					debug!("Web-socket, write pending messages");
					if let Err(e) = web_socket.write_pending() {
						match e {
							tungstenite::Error::ConnectionClosed => is_closing = true,
							_ => error!("Failed to write pending web-socket messages: {:?}", e),
						}
					}
				}
			}
		}

		if is_closing {
			debug!("Connection ({:?}) is closed", self.connection_token);
			self.is_closed = true;
		} else {
			debug!("Re-registering connection {:?}", self.connection_token);
			// Re-register with the poll.
			self.reregister(poll)?;
		}
		Ok(())
	}

	fn do_tls_read(&mut self) -> ConnectionState {
		debug!("doing TLS read");
		let tls_stream = self.get_active_stream_mut();
		let tls_session = &mut tls_stream.sess;

		match tls_session.read_tls(&mut tls_stream.sock) {
			Ok(r) =>
				if r == 0 {
					debug!("TLS stream encountered eof");
					return ConnectionState::Closing
				},
			Err(err) =>
				if let std::io::ErrorKind::WouldBlock = err.kind() {
					debug!("TLS read returns WouldBlock");
					return ConnectionState::Blocked
				},
		}

		match tls_session.process_new_packets() {
			Ok(_) => {
				debug!("TLS read successful, connection is alive");
				if tls_session.is_handshaking() {
					return ConnectionState::TlsHandshake
				}
				ConnectionState::Alive
			},
			Err(e) => {
				error!("cannot process TLS packet(s): {:?}", e);
				ConnectionState::Closing
			},
		}
	}

	fn do_tls_write(&mut self) -> ConnectionState {
		let tls_stream = self.get_active_stream_mut();
		match tls_stream.sess.write_tls(&mut tls_stream.sock) {
			Ok(_) => {
				debug!("TLS write successful, connection is alive");
				if tls_stream.sess.is_handshaking() {
					return ConnectionState::TlsHandshake
				}
				ConnectionState::Alive
			},
			Err(e) => {
				error!("TLS write error: {:?}", e);
				ConnectionState::Closing
			},
		}
	}

	fn read_or_initialize_websocket(&mut self) -> WebSocketResult<bool> {
		match self.web_socket.as_mut() {
			None => {
				debug!("Initiating websocket handshake..");
				let tls_stream = self
					.tls_stream
					.take()
					.ok_or(WebSocketError::HandShakeError("Missing TLS stream".to_string()))?;

				self.web_socket = Some(
					accept(tls_stream)
						.map_err(|e| WebSocketError::HandShakeError(format!("{:?}", e)))?,
				);
				debug!("Handshake successful");
			},
			Some(web_socket) => match web_socket.read_message() {
				Ok(m) =>
					if let Err(e) = self.handle_message(m) {
						error!("Failed to handle web-socket message: {:?}", e);
					},
				Err(e) => match e {
					tungstenite::Error::ConnectionClosed => return Ok(true),
					_ => error!("Failed to read message from web-socket: {:?}", e),
				},
			},
		}
		Ok(false)
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
		match self.web_socket.as_mut() {
			Some(web_socket) => {
				if !web_socket.can_write() {
					return Err(WebSocketError::ConnectionClosed)
				}

				web_socket
					.write_message(Message::Text(message))
					.map_err(|e| WebSocketError::SocketWriteError(format!("{:?}", e)))
			},
			None =>
				Err(WebSocketError::SocketWriteError(format!("No active web-socket available"))),
		}
	}

	pub fn is_closed(&self) -> bool {
		self.is_closed
	}
}

#[derive(Debug, Clone)]
enum ConnectionState {
	Closing,
	Blocked,
	Alive,
	TlsHandshake,
}

// impl<'a, Handler> WebSocketConnection for TungsteniteWsConnection<'a, Handler>
// where
// 	Handler: WebSocketHandler,
// {
// 	fn id(&self) -> Token {
// 		self.connection_token
// 	}
//
// 	fn read_message(&mut self) -> WebSocketResult<Message> {
// 		self.web_socket.read_message().map_err(|_| WebSocketError::ConnectionClosed)
// 	}
//
// 	fn write_pending(&mut self) -> WebSocketResult<()> {
// 		self.web_socket.write_pending().map_err(|_| WebSocketError::ConnectionClosed)
// 	}
//
// 	fn process_request<F>(&mut self, initial_call: F) -> WebSocketResult<String>
// 	where
// 		F: Fn(&str) -> String,
// 	{
// 		debug!("processing web socket request");
//
// 		let request = String::default(); //self.read_next_message()?;
//
// 		let response = (initial_call)(request.as_str());
//
// 		self.write_message(response.clone())?;
//
// 		debug!("successfully processed web socket request");
// 		Ok(response)
// 	}
//
// 	fn send_update(&mut self, message: String) -> WebSocketResult<()> {
// 		debug!("sending web socket update");
// 		self.write_message(message)
// 	}
//
// 	fn close(&mut self) {
// 		match self.web_socket.close(None) {
// 			Ok(()) => {
// 				debug!("web socket connection closed");
// 			},
// 			Err(e) => {
// 				error!("failed to close web socket connection (already closed?): {:?}", e);
// 			},
// 		}
//
// 		match self.web_socket.write_pending() {
// 			Ok(()) => {
// 				debug!("write_pending succeeded");
// 			},
// 			Err(e) => {
// 				// a closed error is to be expected here (according to '.close()' documentation
// 				debug!("flushed connection after closing, received error information: {:?}", e);
// 			},
// 		}
// 	}
// }
