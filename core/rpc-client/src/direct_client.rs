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

//! Interface for direct access to a workers rpc.

use crate::ws_client::{WsClient, WsClientControl};
use codec::Decode;
use frame_metadata::RuntimeMetadataPrefixed;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_types::DirectRequestStatus;
use itp_utils::FromHexPrefixed;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use std::{
	sync::{
		mpsc::{channel, Sender as MpscSender},
		Arc,
	},
	thread,
	thread::JoinHandle,
};

pub use crate::error::{Error, Result};

#[derive(Clone)]
pub struct DirectClient {
	url: String,
	web_socket_control: Arc<WsClientControl>,
}
pub trait DirectApi {
	/// Server connection with only one response.
	fn get(&self, request: &str) -> Result<String>;
	/// Server connection with more than one response.
	fn watch(&self, request: String, sender: MpscSender<String>) -> JoinHandle<()>;
	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey>;
	fn get_mu_ra_url(&self) -> Result<String>;
	fn get_untrusted_worker_url(&self) -> Result<String>;
	fn get_state_metadata(&self) -> Result<RuntimeMetadataPrefixed>;

	fn send(&self, request: &str) -> Result<()>;
	/// Close any open websocket connection.
	fn close(&self) -> Result<()>;
}

impl DirectClient {
	pub fn new(url: String) -> Self {
		Self { url, web_socket_control: Default::default() }
	}
}

impl Drop for DirectClient {
	fn drop(&mut self) {
		if let Err(e) = self.close() {
			error!("Failed to close web-socket connection: {:?}", e);
		}
	}
}

impl DirectApi for DirectClient {
	fn get(&self, request: &str) -> Result<String> {
		let (port_in, port_out) = channel();

		info!("[WorkerApi Direct]: (get) Sending request: {:?}", request);
		WsClient::connect_one_shot(&self.url, request, port_in)?;
		debug!("Waiting for web-socket result..");
		port_out.recv().map_err(Error::MspcReceiver)
	}

	fn watch(&self, request: String, sender: MpscSender<String>) -> JoinHandle<()> {
		info!("[WorkerApi Direct]: (watch) Sending request: {:?}", request);
		let url = self.url.clone();

		let web_socket_control = self.web_socket_control.clone();
		// Unwrap is fine here, because JoinHandle can be used to handle a Thread panic.
		thread::spawn(move || {
			WsClient::connect_watch_with_control(&url, &request, &sender, web_socket_control)
				.expect("Connection failed")
		})
	}

	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey> {
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(
			"author_getShieldingKey".to_string(),
			Default::default(),
		)?;

		// Send json rpc call to ws server.
		let response_str = self.get(&jsonrpc_call)?;

		let shielding_pubkey_string = decode_from_rpc_response(&response_str)?;
		let shielding_pubkey: Rsa3072PubKey = serde_json::from_str(&shielding_pubkey_string)?;

		info!("[+] Got RSA public key of enclave");
		Ok(shielding_pubkey)
	}

	fn get_mu_ra_url(&self) -> Result<String> {
		let jsonrpc_call: String =
			RpcRequest::compose_jsonrpc_call("author_getMuRaUrl".to_string(), Default::default())?;

		// Send json rpc call to ws server.
		let response_str = self.get(&jsonrpc_call)?;

		let mu_ra_url: String = decode_from_rpc_response(&response_str)?;

		info!("[+] Got mutual remote attestation url of enclave: {}", mu_ra_url);
		Ok(mu_ra_url)
	}

	fn get_untrusted_worker_url(&self) -> Result<String> {
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(
			"author_getUntrustedUrl".to_string(),
			Default::default(),
		)?;

		// Send json rpc call to ws server.
		let response_str = self.get(&jsonrpc_call)?;

		let untrusted_url: String = decode_from_rpc_response(&response_str)?;

		info!("[+] Got untrusted websocket url of worker: {}", untrusted_url);
		Ok(untrusted_url)
	}

	fn get_state_metadata(&self) -> Result<RuntimeMetadataPrefixed> {
		let jsonrpc_call: String =
			RpcRequest::compose_jsonrpc_call("state_getMetadata".to_string(), Default::default())?;

		// Send json rpc call to ws server.
		let response_str = self.get(&jsonrpc_call)?;

		// Decode rpc response.
		let rpc_response: RpcResponse = serde_json::from_str(&response_str)?;
		let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
			.map_err(|e| Error::Custom(Box::new(e)))?;

		// Decode Metadata.
		let metadata = RuntimeMetadataPrefixed::decode(&mut rpc_return_value.value.as_slice())?;

		println!("[+] Got metadata of enclave runtime");
		Ok(metadata)
	}

	fn send(&self, request: &str) -> Result<()> {
		self.web_socket_control.send(request)
	}

	fn close(&self) -> Result<()> {
		self.web_socket_control.close_connection()
	}
}

fn decode_from_rpc_response(json_rpc_response: &str) -> Result<String> {
	let rpc_response: RpcResponse = serde_json::from_str(json_rpc_response)?;
	let rpc_return_value =
		RpcReturnValue::from_hex(&rpc_response.result).map_err(|e| Error::Custom(Box::new(e)))?;
	let response_message = String::decode(&mut rpc_return_value.value.as_slice())?;
	match rpc_return_value.status {
		DirectRequestStatus::Ok => Ok(response_message),
		_ => Err(Error::Status(response_message)),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itc_tls_websocket_server::{test::fixtures::test_server::create_server, WebSocketServer};
	use itp_networking_utils::ports::get_available_port_in_range;
	use std::vec;

	#[test]
	fn watch_works_and_closes_connection_on_demand() {
		let _ = env_logger::builder().is_test(true).try_init();

		const END_MESSAGE: &str = "End of service.";
		let responses = vec![END_MESSAGE.to_string()];

		let port = get_available_port_in_range(21000..21500).unwrap();
		let (server, handler) = create_server(responses, port);

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || {
			if let Err(e) = server_clone.run() {
				error!("Web-socket server failed: {:?}", e);
			}
		});

		// Wait until server is up.
		while !server.is_running().unwrap() {
			thread::sleep(std::time::Duration::from_millis(50));
		}

		let client = DirectClient::new(format!("wss://localhost:{}", port));
		let (message_sender, message_receiver) = channel::<String>();

		let client_join_handle = client.watch("Request".to_string(), message_sender);

		let mut messages = Vec::<String>::new();
		loop {
			info!("Client waiting to receive answer.. ");
			let message = message_receiver.recv().unwrap();
			info!("Received answer: {}", message);
			let do_close = message.as_str() == END_MESSAGE;
			messages.push(message);

			if do_close {
				info!("Client closing connection");
				break
			}
		}

		info!("Joining client thread");
		client.close().unwrap();
		client_join_handle.join().unwrap();

		info!("Joining server thread");
		server.shut_down().unwrap();
		server_join_handle.join().unwrap();

		assert_eq!(1, messages.len());
		assert_eq!(1, handler.messages_handled.read().unwrap().len());
	}

	#[test]
	fn get_works_and_closes_connection() {
		let _ = env_logger::builder().is_test(true).try_init();

		let server_response = "response 1".to_string();
		let responses = vec![server_response.clone()];

		let port = get_available_port_in_range(21501..22000).unwrap();
		let (server, handler) = create_server(responses, port);

		let server_clone = server.clone();
		let server_join_handle = thread::spawn(move || {
			if let Err(e) = server_clone.run() {
				error!("Web-socket server failed: {:?}", e);
			}
		});

		// Wait until server is up.
		while !server.is_running().unwrap() {
			thread::sleep(std::time::Duration::from_millis(50));
		}

		let client = DirectClient::new(format!("wss://localhost:{}", port));
		let received_response = client.get("Request").unwrap();

		info!("Joining server thread");
		server.shut_down().unwrap();
		server_join_handle.join().unwrap();

		assert_eq!(server_response, received_response);
		assert_eq!(1, handler.messages_handled.read().unwrap().len());
	}
}
