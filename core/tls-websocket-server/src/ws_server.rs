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
	ConnectionIdGenerator, ConnectionToken, WebSocketConnection, WebSocketMessageHandler,
	WebSocketResponder, WebSocketServer,
};
use log::*;
use mio::{
	event::{Event, Evented},
	net::TcpListener,
	Poll,
};
use mio_extras::channel::{channel, Receiver, Sender};
use net::SocketAddr;
use rustls::ServerConfig;
use std::{collections::HashMap, format, net, string::String, sync::Arc};

// Default tokens for the server.
pub(crate) const NEW_CONNECTIONS_LISTENER: mio::Token = mio::Token(0);
pub(crate) const SERVER_SIGNAL_TOKEN: mio::Token = mio::Token(1);

/// Secure web-socket server implementation using the Tungstenite library.
pub struct TungsteniteWsServer<Handler, ConfigProvider> {
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
	Handler: WebSocketMessageHandler,
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
		trace!("New connection has token {:?}", token);

		let mut web_socket_connection = TungsteniteWsConnection::new(
			socket,
			tls_session,
			token,
			self.connection_handler.clone(),
		)?;

		trace!("Web-socket connection created");
		web_socket_connection.register(poll)?;

		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;
		connections_lock.insert(token, web_socket_connection);

		trace!("Successfully accepted connection");
		Ok(())
	}

	fn connection_event(&self, poll: &mut mio::Poll, event: &Event) -> WebSocketResult<()> {
		let token = event.token();

		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;

		if let Some(connection) = connections_lock.get_mut(&token) {
			connection.on_ready(poll, event)?;

			if connection.is_closed() {
				trace!("Connection {:?} is closed, removing", token);
				connections_lock.remove(&token);
			}
		}

		Ok(())
	}

	fn handle_server_signal(
		&self,
		poll: &mut mio::Poll,
		event: &Event,
		signal_receiver: &mut Receiver<ServerSignal>,
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
	Handler: WebSocketMessageHandler,
{
	type Connection = TungsteniteWsConnection<Handler>;

	fn run(&self) -> WebSocketResult<()> {
		debug!("Running tungstenite web socket server on {}", self.ws_address);

		let socket_addr: SocketAddr =
			self.ws_address.parse().map_err(WebSocketError::InvalidWsAddress)?;

		let config = self.config_provider.get_config()?;

		let (server_signal_sender, mut shutdown_receiver) = channel::<ServerSignal>();
		self.register_server_signal_sender(server_signal_sender)?;

		let tcp_listener = TcpListener::bind(&socket_addr).map_err(WebSocketError::TcpBindError)?;
		let mut poll = Poll::new()?;
		poll.register(
			&tcp_listener,
			NEW_CONNECTIONS_LISTENER,
			mio::Ready::readable(),
			mio::PollOpt::level(),
		)?;

		poll.register(
			&shutdown_receiver,
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
						trace!("Received new connection event");
						if let Err(e) =
							self.accept_connection(&mut poll, &tcp_listener, config.clone())
						{
							error!("Failed to accept new web-socket connection: {:?}", e);
						}
					},
					SERVER_SIGNAL_TOKEN => {
						trace!("Received server signal event");
						if self.handle_server_signal(&mut poll, &event, &mut shutdown_receiver)? {
							break 'outer_event_loop
						}
					},
					_ => {
						trace!("Connection (token {:?}) activity event", event.token());
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

impl<Handler, ConfigProvider> WebSocketResponder for TungsteniteWsServer<Handler, ConfigProvider>
where
	ConfigProvider: ProvideServerConfig,
	Handler: WebSocketMessageHandler,
{
	fn send_message(
		&self,
		connection_token: ConnectionToken,
		message: String,
	) -> WebSocketResult<()> {
		let mut connections_lock =
			self.connections.write().map_err(|_| WebSocketError::LockPoisoning)?;
		let connection = connections_lock
			.get_mut(&connection_token.into())
			.ok_or(WebSocketError::InvalidConnection(connection_token.0))?;
		connection.write_message(message)
	}
}

/// Internal server signal enum.
enum ServerSignal {
	ShutDown,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::{
		fixtures::{no_cert_verifier::NoCertVerifier, test_server::create_server},
		mocks::web_socket_handler_mock::WebSocketHandlerMock,
	};
	use alloc::collections::VecDeque;
	use rustls::ClientConfig;
	use std::{net::TcpStream, thread, time::Duration};
	use tungstenite::{
		client_tls_with_config, stream::MaybeTlsStream, Connector, Message, WebSocket,
	};
	use url::Url;

	#[test]
	fn server_handles_multiple_connections() {
		let _ = env_logger::builder().is_test(true).try_init();

		let expected_answer = "websocket server response bidibibup".to_string();
		let port: u16 = 21777;
		const NUMBER_OF_CONNECTIONS: usize = 20;

		let responses: VecDeque<_> =
			(0..NUMBER_OF_CONNECTIONS).map(|_| expected_answer.clone()).collect();
		let (server, handler) = create_server(responses, port);

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || server_clone.run());

		// Wait until server is up.
		thread::sleep(std::time::Duration::from_millis(50));

		// Spawn multiple clients that connect to the server simultaneously and send a message.
		let client_handles: Vec<_> = (0..NUMBER_OF_CONNECTIONS)
			.map(|_| {
				let expected_answer_clone = expected_answer.clone();

				thread::spawn(move || {
					let mut socket = connect_tls_client(get_server_addr(port).as_str());
					socket
						.write_message(Message::Text("Hello WebSocket".into()))
						.expect("client write message to be successful");

					assert_eq!(
						Message::Text(expected_answer_clone),
						socket.read_message().unwrap()
					);
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

		assert_eq!(NUMBER_OF_CONNECTIONS, handler.get_handled_messages().len());
	}

	#[test]
	fn server_sends_update_message_to_client() {
		let _ = env_logger::builder().is_test(true).try_init();

		let expected_answer = "first response".to_string();
		let port: u16 = 21778;
		let (server, handler) = create_server(VecDeque::from([expected_answer.clone()]), port);

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || server_clone.run());

		// Wait until server is up.
		thread::sleep(std::time::Duration::from_millis(50));

		let update_message = "Message update".to_string();
		let update_message_clone = update_message.clone();

		let client_join_handle = thread::spawn(move || {
			let mut socket = connect_tls_client(get_server_addr(port).as_str());
			socket
				.write_message(Message::Text("First request".into()))
				.expect("client write message to be successful");

			assert_eq!(Message::Text(expected_answer), socket.read_message().unwrap());
			assert_eq!(Message::Text(update_message_clone), socket.read_message().unwrap());
		});

		let connection_token = poll_handler_for_first_connection(handler.as_ref());

		// Send reply to a wrong connection token, should fail.
		assert!(server
			.send_message(
				ConnectionToken(connection_token.0 + 1),
				"wont get to the client".to_string()
			)
			.is_err());

		// Send reply to the correct connection token.
		server.send_message(connection_token, update_message).unwrap();

		client_join_handle.join().unwrap();
		server.shut_down().unwrap();
		server_join_handle.join().unwrap().unwrap();

		assert_eq!(1, handler.get_handled_messages().len());
	}

	// Ignored because it does not directly test any of our own components.
	// It was used to test the behavior of the tungstenite client configuration with certificates.
	#[test]
	#[ignore]
	fn client_test() {
		let mut socket = connect_tls_client("ws.ifelse.io:443");

		socket
			.write_message(Message::Text("Hello WebSocket".into()))
			.expect("client write message to be successful");
	}

	fn poll_handler_for_first_connection(handler: &WebSocketHandlerMock) -> ConnectionToken {
		loop {
			match handler.get_handled_messages().first() {
				None => thread::sleep(Duration::from_millis(5)),
				Some(m) => return m.0,
			}
		}
	}

	fn get_server_addr(port: u16) -> String {
		format!("localhost:{}", port)
	}

	fn connect_tls_client(server_addr: &str) -> WebSocket<MaybeTlsStream<TcpStream>> {
		let ws_server_url = Url::parse(format!("wss://{}", server_addr).as_str()).unwrap();

		let mut config = ClientConfig::new();
		config.dangerous().set_certificate_verifier(Arc::new(NoCertVerifier {}));
		let connector = Connector::Rustls(Arc::new(config));
		let stream = TcpStream::connect(server_addr).unwrap();

		let (socket, _response) =
			client_tls_with_config(ws_server_url, stream, None, Some(connector))
				.expect("Can't connect");

		socket
	}
}
