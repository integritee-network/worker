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

#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, SgxRwLock as RwLock};

#[cfg(feature = "std")]
use std::sync::{Mutex, RwLock};

use crate::{
	config_provider::ProvideServerConfig,
	connection::TungsteniteWsConnection,
	connection_id_generator::GenerateConnectionId,
	error::{WebSocketError, WebSocketResult},
	ConnectionIdGenerator, WebSocketHandler, WebSocketServer,
};
use log::*;
use mio::{
	channel::{channel, Sender},
	net::TcpListener,
	Evented, Poll,
};
use net::SocketAddr;
use rustls::ServerConfig;
use std::{collections::HashMap, net, string::String, sync::Arc};

// Default tokens for the server.
const NEW_CONNECTIONS_LISTENER: mio::Token = mio::Token(0);
const SERVER_SIGNAL_TOKEN: mio::Token = mio::Token(1);

/// Secure web-socket server implementation using the tungstenite library
pub(crate) struct TungsteniteWsServer<Handler, ConfigProvider> {
	ws_address: String,
	config_provider: Arc<ConfigProvider>,
	connection_handler: Arc<Handler>,
	id_generator: ConnectionIdGenerator,
	connections: RwLock<HashMap<mio::Token, TungsteniteWsConnection<Handler>>>,
	signal_sender: Mutex<Option<Sender<ServerSignal>>>,
}

impl<Handler, ConfigProvider> TungsteniteWsServer<Handler, ConfigProvider>
where
	ConfigProvider: ProvideServerConfig,
	Handler: WebSocketHandler,
{
	pub fn new(
		ws_address: String,
		config_provider: Arc<ConfigProvider>,
		connection_handler: Arc<Handler>,
	) -> Self {
		TungsteniteWsServer {
			ws_address,
			config_provider,
			connection_handler,
			id_generator: ConnectionIdGenerator::default(),
			connections: Default::default(),
			signal_sender: Default::default(),
		}
	}

	fn accept_connection(
		&self,
		poll: &mut Poll,
		tcp_listener: &TcpListener,
		tls_config: Arc<ServerConfig>,
	) -> WebSocketResult<()> {
		let (socket, addr) = tcp_listener.accept()?;

		debug!("Accepting new connection from {:?}", addr);

		let tls_session = rustls::ServerSession::new(&tls_config);
		let connection_id = self.id_generator.next_id()?;
		let token = mio::Token(connection_id);

		let mut web_socket_connection = TungsteniteWsConnection::connect(
			socket,
			tls_session,
			token,
			self.connection_handler.clone(),
		)?;
		web_socket_connection.register(poll)?;

		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;
		connections_lock.insert(token, web_socket_connection);

		Ok(())
	}

	fn connection_event(
		&self,
		poll: &mut mio::Poll,
		event: &mio::event::Event,
	) -> WebSocketResult<()> {
		let token = event.token();

		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;

		if let Some(connection) = connections_lock.get_mut(&token) {
			connection.ready(poll, event)?;

			if connection.is_closed() {
				connections_lock.remove(&token);
			}
		}

		Ok(())
	}

	fn handle_server_signal(
		&self,
		poll: &mut mio::Poll,
		event: &mio::event::Event,
		signal_receiver: &mut mio::channel::Receiver<ServerSignal>,
	) -> WebSocketResult<bool> {
		let signal = signal_receiver.try_recv()?;

		let initiate_shut_down = match signal {
			ServerSignal::ShutDown => true,
		};

		signal_receiver.reregister(
			poll,
			event.token(),
			mio::Ready::readable(),
			mio::PollOpt::level(),
		)?;

		Ok(initiate_shut_down)
	}

	fn register_server_signal_sender(&self, sender: Sender<ServerSignal>) -> WebSocketResult<()> {
		let mut sender_lock =
			self.signal_sender.lock().map_err(|_| WebSocketError::LockPoisoning)?;
		*sender_lock = Some(sender);
		Ok(())
	}
}

impl<Handler, ConfigProvider> WebSocketServer for TungsteniteWsServer<Handler, ConfigProvider>
where
	ConfigProvider: ProvideServerConfig,
	Handler: WebSocketHandler,
{
	type Connection = TungsteniteWsConnection<Handler>;

	fn run(&self) -> WebSocketResult<()> {
		debug!("Running tungstenite web socket server on {}", self.ws_address);

		let socket_addr: SocketAddr =
			self.ws_address.parse().map_err(WebSocketError::InvalidWsAddress)?;

		let config = self.config_provider.get_config()?;

		let (server_signal_sender, mut shutdown_receiver) = channel::<ServerSignal>();
		self.register_server_signal_sender(server_signal_sender)?;

		let mut tcp_listener =
			TcpListener::bind(&socket_addr).map_err(WebSocketError::TcpBindError)?;
		let mut poll = Poll::new()?;
		poll.register(
			&mut tcp_listener,
			NEW_CONNECTIONS_LISTENER,
			mio::Ready::readable(),
			mio::PollOpt::level(),
		)?;

		poll.register(
			&mut shutdown_receiver,
			SERVER_SIGNAL_TOKEN,
			mio::Ready::readable(),
			mio::PollOpt::level(),
		)?;

		let mut events = mio::Events::with_capacity(1024);

		// Run the event loop.
		'outer_event_loop: loop {
			poll.poll(&mut events, None)?;

			for event in events.iter() {
				match event.token() {
					NEW_CONNECTIONS_LISTENER => {
						if let Err(e) =
							self.accept_connection(&mut poll, &mut tcp_listener, config.clone())
						{
							error!("Failed to accept new web-socket connection: {:?}", e);
						}
					},
					SERVER_SIGNAL_TOKEN => {
						if self.handle_server_signal(&mut poll, &event, &mut shutdown_receiver)? {
							break 'outer_event_loop
						}
					},
					_ =>
						if let Err(e) = self.connection_event(&mut poll, &event) {
							error!("Failed to process connection event: {:?}", e);
						},
				}
			}
		}

		info!("Web-socket server has shut down");
		Ok(())
	}

	fn shut_down(&self) -> WebSocketResult<()> {
		info!("Shutdown request of web-socket server detected, shutting down..");
		match self.signal_sender.lock().map_err(|_| WebSocketError::LockPoisoning)?.as_ref() {
			None => {
				warn!(
					"Signal sender has not been initialized, cannot send web-socket server signal"
				);
			},
			Some(signal_sender) => {
				signal_sender
					.send(ServerSignal::ShutDown)
					.map_err(|e| WebSocketError::Other(format!("{:?}", e).into()))?;
			},
		}

		Ok(())
	}
}

pub(crate) enum ServerSignal {
	ShutDown,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::{
		fixtures::test_server_config_provider::TestServerConfigProvider,
		mocks::web_socket_handler_mock::WebSocketHandlerMock,
	};
	use core::time::Duration;
	use std::thread;

	#[test]
	fn server_handles_multiple_connections() {
		let _ = env_logger::builder().is_test(true).try_init();

		let config_provider = Arc::new(TestServerConfigProvider {});
		let handler = Arc::new(WebSocketHandlerMock::new(None));

		let server = Arc::new(TungsteniteWsServer::new(
			"127.0.0.1:6677".to_string(),
			config_provider,
			handler,
		));

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || server_clone.run());

		thread::sleep(Duration::from_millis(100));
		server.shut_down().unwrap();

		let server_shutdown_result = server_join_handle.join().unwrap();
		if let Err(e) = server_shutdown_result {
			panic!("Test failed, web-socket returned error: {:?}", e);
		}
	}
}
