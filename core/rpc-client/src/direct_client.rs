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

use crate::ws_client::WsClient;
use codec::Decode;
use itp_types::{DirectRequestStatus, RpcRequest, RpcResponse, RpcReturnValue};
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use std::sync::mpsc::{channel, Sender as MpscSender};

pub use crate::error::{Error, Result};

#[derive(Clone)]
pub struct DirectClient {
	url: String,
}
pub trait DirectApi {
	fn watch(&self, request: &str, sender: &MpscSender<String>) -> Result<()>;
	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey>;
}

impl DirectClient {
	pub fn new(url: String) -> Self {
		Self { url }
	}

	/// Server connection with only one response.
	pub fn get(&self, request: &str) -> Result<String> {
		let (port_in, port_out) = channel();

		info!("[WorkerApi Direct]: (get) Sending request: {:?}", request);
		WsClient::connect(&self.url, request, &port_in, false)?;
		port_out.recv().map_err(Error::MspcReceiver)
	}
}

impl DirectApi for DirectClient {
	/// Server connection with more than one response.
	fn watch(&self, request: &str, sender: &MpscSender<String>) -> Result<()> {
		info!("[WorkerApi Direct]: (watch) Sending request: {:?}", request);
		WsClient::connect(&self.url, request, sender, true).map_err(Error::WsClientError)
	}

	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey> {
		// compose jsonrpc call
		let method = "author_getShieldingKey".to_owned();
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(method, vec![]);

		let response_str = Self::get(self, &jsonrpc_call)?;

		// decode result
		let response: RpcResponse = serde_json::from_str(&response_str)?;
		let return_value = RpcReturnValue::decode(&mut response.result.as_slice())?;
		let shielding_pubkey_string: String = match return_value.status {
			DirectRequestStatus::Ok => String::decode(&mut return_value.value.as_slice())?,
			_ => {
				let error_message = String::decode(&mut return_value.value.as_slice())?;
				return Err(Error::Status(error_message))
			},
		};
		let shielding_pubkey: Rsa3072PubKey = serde_json::from_str(&shielding_pubkey_string)?;

		info!("[+] Got RSA public key of enclave");
		Ok(shielding_pubkey)
	}

	/* fn get_mu_ra_url(&self) -> Result<String> {
		// compose jsonrpc call
		let method = "author_getMuRaUrl".to_owned();
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(method, vec![]);

		let response_str = match Self::get(self, jsonrpc_call) {
			Ok(resp) => resp,
			Err(err_msg) =>
				return Err(format! {"Could not retrieve shielding pubkey: {:?}", err_msg}),
		};

		// decode result
		let response: RpcResponse = match serde_json::from_str(&response_str) {
			Ok(resp) => resp,
			Err(err_msg) =>
				return Err(format! {"Could not retrieve shielding pubkey: {:?}", err_msg}),
		};
		let return_value = match RpcReturnValue::decode(&mut response.result.as_slice()) {
			Ok(val) => val,
			Err(err_msg) =>
				return Err(format! {"Could not retrieve shielding pubkey: {:?}", err_msg}),
		};
		let shielding_pubkey_string: String = match return_value.status {
			DirectRequestStatus::Ok => match String::decode(&mut return_value.value.as_slice()) {
				Ok(key) => key,
				Err(err) => return Err(format! {"Could not retrieve shielding pubkey: {:?}", err}),
			},
			_ => match String::decode(&mut return_value.value.as_slice()) {
				Ok(err_msg) =>
					return Err(format! {"Could not retrieve shielding pubkey: {}", err_msg}),
				Err(err) => return Err(format! {"Could not retrieve shielding pubkey: {:?}", err}),
			},
		};
		let shielding_pubkey: Rsa3072PubKey = match serde_json::from_str(&shielding_pubkey_string) {
			Ok(key) => key,
			Err(err) => return Err(format! {"Could not retrieve shielding pubkey: {:?}", err}),
		};

		info!("[+] Got RSA public key of enclave");
		Ok(shielding_pubkey)
	} */
}
