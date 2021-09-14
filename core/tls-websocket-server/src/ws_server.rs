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
	common::make_config, connection::TungsteniteWsConnection, WebSocketError, WebSocketHandler,
	WebSocketResult, WebSocketServer,
};
use log::*;
use net::SocketAddr;
use rustls::ServerSession;
use std::{net, net::TcpListener, string::String, sync::Arc};

/// Secure web-socket server implementation using the tungstenite library
pub struct TungsteniteWsServer {
	ws_address: String,
	cert_path: String,
	private_key_path: String,
}

impl TungsteniteWsServer {
	pub fn new(ws_address: String, cert_path: String, private_key_path: String) -> Self {
		TungsteniteWsServer { ws_address, cert_path, private_key_path }
	}
}

impl WebSocketServer for TungsteniteWsServer {
	type Connection = TungsteniteWsConnection;

	fn run<Handler>(&self, handler: Arc<Handler>) -> WebSocketResult<()>
	where
		Handler: WebSocketHandler<Connection = Self::Connection>,
	{
		debug!("Running tungstenite web socket server on {}", self.ws_address);

		let socket_addr: SocketAddr =
			self.ws_address.parse().map_err(WebSocketError::InvalidWsAddress)?;

		let config = make_config(self.cert_path.as_str(), self.private_key_path.as_str())?;

		let listener = TcpListener::bind(&socket_addr).map_err(WebSocketError::TcpBindError)?;

		loop {
			let stream_result = listener.accept();

			match stream_result {
				Ok((stream, _)) => {
					let cloned_config = config.clone();

					let server_session = ServerSession::new(&cloned_config);

					let connection = match TungsteniteWsConnection::connect(stream, server_session)
					{
						Ok(c) => c,
						Err(e) => {
							error!("failed to establish web-socket connection: {:?}", e);
							continue
						},
					};

					// continue serving requests, even if there is an error in handling a specific connection
					if let Err(handler_error) = handler.handle(connection) {
						error!("web-socket request failed: {:?}", handler_error);
					}
				},
				Err(e) => {
					warn!("failed to establish web-socket connection ({:?})", e)
				},
			}
		}
	}
}
