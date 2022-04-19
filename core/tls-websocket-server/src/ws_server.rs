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
		debug!("New connection has token {:?}", token);

		let mut web_socket_connection = TungsteniteWsConnection::connect(
			socket,
			tls_session,
			token,
			self.connection_handler.clone(),
		)?;

		debug!("Web-socket connection created");
		web_socket_connection.register(poll)?;

		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;
		connections_lock.insert(token, web_socket_connection);

		debug!("Successfully accepted connection");
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
				debug!("Connection {:?} is closed, removing", token);
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
						debug!("Received new connection event");
						if let Err(e) =
							self.accept_connection(&mut poll, &mut tcp_listener, config.clone())
						{
							error!("Failed to accept new web-socket connection: {:?}", e);
						}
					},
					SERVER_SIGNAL_TOKEN => {
						debug!("Received server signal event");
						if self.handle_server_signal(&mut poll, &event, &mut shutdown_receiver)? {
							break 'outer_event_loop
						}
					},
					_ => {
						debug!("Connection (token {:?}) activity event", event.token());
						if let Err(e) = self.connection_event(&mut poll, &event) {
							error!("Failed to process connection event: {:?}", e);
						}
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
		fixtures::{
			no_cert_verifier::NoCertVerifier, test_server_config_provider::TestServerConfigProvider,
		},
		mocks::web_socket_handler_mock::WebSocketHandlerMock,
	};
	use rustls::ClientConfig;
	use std::{net::TcpStream, thread};
	use tungstenite::{
		client::connect as client_connect, client_tls_with_config, stream::MaybeTlsStream,
		Connector, Message, WebSocket,
	};
	use url::Url;

	#[test]
	fn server_handles_multiple_connections() {
		let _ = env_logger::builder().is_test(false).try_init();

		let config_provider = Arc::new(TestServerConfigProvider {});
		let handler = Arc::new(WebSocketHandlerMock::new(Some(
			"websocket server response bidibibup".to_string(),
		)));

		let server_addr_string: String = "127.0.0.1:21777".to_string();

		let server = Arc::new(TungsteniteWsServer::new(
			server_addr_string.clone(),
			config_provider,
			handler.clone(),
		));

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || server_clone.run());

		thread::sleep(std::time::Duration::from_millis(100));

		let client_handles: Vec<_> = (0..1)
			.map(|_| {
				let server_addr_str_clone = "localhost:21777".to_string();

				thread::spawn(move || {
					let mut socket = connect_tls_client(server_addr_str_clone.as_str());
					socket
						.write_message(Message::Text("Hello WebSocket".into()))
						.expect("client write message to be successful");
				})
			})
			.collect();

		for handle in client_handles.into_iter() {
			handle.join().expect("client handle to be joined");
		}

		server.shut_down().unwrap();

		let server_shutdown_result =
			server_join_handle.join().expect("Couldn't join on the associated thread");
		if let Err(e) = server_shutdown_result {
			panic!("Test failed, web-socket returned error: {:?}", e);
		}

		assert_eq!(6, handler.get_handled_messages().len());
	}

	fn connect_tls_client(server_addr: &str) -> WebSocket<MaybeTlsStream<TcpStream>> {
		let ws_server_url = Url::parse(format!("wss://{}", server_addr).as_str()).unwrap();

		let mut config = ClientConfig::new();
		config.dangerous().set_certificate_verifier(Arc::new(NoCertVerifier {}));
		let connector = Connector::Rustls(Arc::new(config));
		let stream = TcpStream::connect(server_addr).unwrap();

		let (mut socket, _response) =
			client_tls_with_config(ws_server_url, stream, None, Some(connector))
				.expect("Can't connect");

		socket
	}

	#[test]
	#[ignore]
	fn client_test() {
		let mut socket = connect_tls_client("ws.ifelse.io:443");

		socket
			.write_message(Message::Text("Hello WebSocket".into()))
			.expect("client write message to be successful");
	}
}
