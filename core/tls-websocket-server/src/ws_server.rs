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

use crate::{
	common::make_config,
	connection::TungsteniteWsConnection,
	connection_id_generator::GenerateConnectionId,
	error::{WebSocketError, WebSocketResult},
	WebSocketHandler, WebSocketServer,
};
use log::*;
use mio::{net::TcpListener, Poll};
use net::SocketAddr;
use rustls::{ServerConfig, ServerSession};
use std::{collections::HashMap, net, string::String, sync::Arc};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

/// Secure web-socket server implementation using the tungstenite library
pub struct TungsteniteWsServer<IdGenerator> {
	ws_address: String,
	cert_path: String,
	private_key_path: String,
	id_generator: Arc<IdGenerator>,
	connections: HashMap<mio::Token, TungsteniteWsConnection>,
}

impl<IdGenerator> TungsteniteWsServer<IdGenerator>
where
	IdGenerator: GenerateConnectionId,
{
	pub fn new(
		ws_address: String,
		cert_path: String,
		private_key_path: String,
		id_generator: Arc<IdGenerator>,
	) -> Self {
		TungsteniteWsServer {
			ws_address,
			cert_path,
			private_key_path,
			id_generator,
			connections: Default::default(),
		}
	}

	fn accept_connection(
		&mut self,
		poll: &mut Poll,
		tcp_listener: &TcpListener,
		tls_config: Arc<ServerConfig>,
	) -> WebSocketResult<()> {
		let (socket, addr) = tcp_listener.accept()?;

		debug!("Accepting new connection from {:?}", addr);

		let tls_session = rustls::ServerSession::new(&tls_config);
		let connection_id = self.id_generator.next_id()?;
		let token = mio::Token(connection_id);

		let web_socket_connection = TungsteniteWsConnection::connect(socket, tls_session, token)?;

		self.connections.insert(token, web_socket_connection);
		self.connections[&token].register(poll)?;

		Ok(())
	}

	fn conn_event(&mut self, poll: &mut mio::Poll, event: &mio::event::Event) {
		let token = event.token();

		if let Some(connection) = self.connections.get_mut(&token) {
			connection.ready(poll, event)?;

			if connection.is_closed() {
				self.connections.remove(&token);
			}
		}
	}
}

impl<IdGenerator> WebSocketServer for TungsteniteWsServer<IdGenerator>
where
	IdGenerator: GenerateConnectionId,
{
	type Connection = TungsteniteWsConnection;

	fn run<Handler>(&mut self, handler: Arc<Handler>) -> WebSocketResult<()>
	where
		Handler: WebSocketHandler<Connection = Self::Connection>,
	{
		debug!("Running tungstenite web socket server on {}", self.ws_address);

		let socket_addr: SocketAddr =
			self.ws_address.parse().map_err(WebSocketError::InvalidWsAddress)?;

		let config = make_config(self.cert_path.as_str(), self.private_key_path.as_str())?;

		let mut listener = TcpListener::bind(&socket_addr).map_err(WebSocketError::TcpBindError)?;
		let mut poll = Poll::new()?;
		poll.register(&mut listener, LISTENER, mio::Ready::readable(), mio::PollOpt::level())?;

		let mut events = mio::Events::with_capacity(1024);

		// Run the event loop.
		'outer: loop {
			poll.poll(&mut events, None)?;

			for event in events.iter() {
				match event.token() {
					LISTENER => {
						if let Err(e) =
							self.accept_connection(&mut poll, &mut listener, config.clone())
						{
							error!("Failed to accept new web-socket connection: {:?}", e);
						}
					},
					_ => tlsserv.conn_event(&mut poll, &event),
				}
			}
		}

		Ok(())

		// loop {
		// 	let stream_result = listener.accept();
		//
		// 	match stream_result {
		// 		Ok((stream, _)) => {
		// 			let cloned_config = config.clone();
		//
		// 			let server_session = ServerSession::new(&cloned_config);
		// 			let next_connection_id = match self.id_generator.next_id() {
		// 				Ok(id) => id,
		// 				Err(e) => {
		// 					error!("Failed to generate next connection id ({:?}), refusing connection attempt", e);
		// 					continue
		// 				},
		// 			};
		//
		// 			let connection = match TungsteniteWsConnection::connect(
		// 				stream,
		// 				server_session,
		// 				next_connection_id,
		// 			) {
		// 				Ok(c) => c,
		// 				Err(e) => {
		// 					error!("failed to establish web-socket connection: {:?}", e);
		// 					continue
		// 				},
		// 			};
		//
		// 			// continue serving requests, even if there is an error in handling a specific connection
		// 			if let Err(handler_error) = handler.handle(connection) {
		// 				error!("web-socket request failed: {:?}", handler_error);
		// 			}
		// 		},
		// 		Err(e) => {
		// 			warn!("failed to establish web-socket connection ({:?})", e)
		// 		},
		// 	}
		// }
	}
}
