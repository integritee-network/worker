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

use crate::error::Result as RpcClientResult;
///! Websocket client implementation to access the direct-rpc-server running inside an enclave.
///
/// This should be replaced with the `jsonrpsee::WsClient`as soon as available in no-std:
/// https://github.com/paritytech/jsonrpsee/issues/1
use log::*;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use parking_lot::Mutex;
use std::sync::{mpsc::Sender as MpscSender, Arc};
use url::{self};
use ws::{connect, util::TcpStream, CloseCode, Handler, Handshake, Message, Result, Sender};

/// Control a registered web-socket client.
#[derive(Default)]
pub struct WsClientControl {
	subscriber: Mutex<Option<Sender>>,
}

impl Clone for WsClientControl {
	fn clone(&self) -> Self {
		WsClientControl { subscriber: Mutex::new(self.subscriber.lock().clone()) }
	}
}

impl WsClientControl {
	pub fn close_connection(&self) -> RpcClientResult<()> {
		if let Some(s) = self.subscriber.lock().as_ref() {
			debug!("Closing connection");
			s.close(CloseCode::Normal)?;
			debug!("Connection is closed");
		}
		Ok(())
	}

	fn subscribe_sender(&self, sender: Sender) -> RpcClientResult<()> {
		let mut subscriber_lock = self.subscriber.lock();
		*subscriber_lock = Some(sender);
		Ok(())
	}
}

#[derive(Clone)]
pub struct WsClient {
	web_socket: Sender,
	request: String,
	result: MpscSender<String>,
	do_watch: bool,
}

impl WsClient {
	/// Connect a web-socket client for multiple request/responses.
	///
	/// Control over the connection is done using the provided client control.
	/// (e.g. shutdown has to be initiated explicitly).
	pub fn connect_watch_with_control(
		url: &str,
		request: &str,
		result: &MpscSender<String>,
		control: Arc<WsClientControl>,
	) -> Result<()> {
		connect(url.to_string(), |out| {
			control.subscribe_sender(out.clone()).unwrap();
			WsClient::new(out, request.to_string(), result.clone(), true)
		})
	}

	/// Connects a web-socket client for a one-shot request.
	pub fn connect_one_shot(url: &str, request: &str, result: &MpscSender<String>) -> Result<()> {
		connect(url.to_string(), |out| {
			WsClient::new(out, request.to_string(), result.clone(), false)
		})
	}

	fn new(
		web_socket: Sender,
		request: String,
		result: MpscSender<String>,
		do_watch: bool,
	) -> WsClient {
		WsClient { web_socket, request, result, do_watch }
	}
}

impl Handler for WsClient {
	fn on_open(&mut self, _: Handshake) -> Result<()> {
		debug!("sending request: {:?}", self.request.clone());
		match self.web_socket.send(self.request.clone()) {
			Ok(_) => Ok(()),
			Err(e) => Err(e),
		}
	}

	fn on_message(&mut self, msg: Message) -> Result<()> {
		trace!("got message");
		trace!("{}", msg);
		trace!("sending result to MpscSender..");
		self.result.send(msg.to_string()).unwrap();
		if !self.do_watch {
			debug!("do_watch is false, closing connection");
			self.web_socket.close(CloseCode::Normal).unwrap();
			debug!("Connection close requested");
		}
		debug!("on_message successful, returning");
		Ok(())
	}

	fn on_close(&mut self, _code: CloseCode, _reason: &str) {
		debug!("Web-socket close");
		self.web_socket.shutdown().unwrap()
	}

	/// we are overriding the `upgrade_ssl_client` method in order to disable hostname verification
	/// this is taken from https://github.com/housleyjk/ws-rs/blob/master/examples/unsafe-ssl-client.rs
	/// TODO: hostname verification should probably be enabled again for production?
	fn upgrade_ssl_client(
		&mut self,
		sock: TcpStream,
		_: &url::Url,
	) -> Result<SslStream<TcpStream>> {
		let mut builder = SslConnector::builder(SslMethod::tls_client()).map_err(|e| {
			ws::Error::new(
				ws::ErrorKind::Internal,
				format!("Failed to upgrade client to SSL: {}", e),
			)
		})?;
		builder.set_verify(SslVerifyMode::empty());

		let connector = builder.build();
		connector
			.configure()
			.unwrap()
			.use_server_name_indication(false)
			.verify_hostname(false)
			.connect("", sock)
			.map_err(From::from)
	}
}
