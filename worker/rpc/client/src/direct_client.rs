///! Interface for direct access to a workers rpc.
///
/// This should be replaced with the `jsonrpsee::WsClient`. It is async an removes a lot of
/// boilerplate code. Example usage in worker/worker.rs.
///
use log::*;
use std::{
	sync::mpsc::{channel, Sender as MpscSender},
	thread,
};

use codec::Decode;

use ws::{connect, CloseCode, Handler, Handshake, Message, Result as ClientResult, Sender};

use substratee_worker_primitives::{DirectRequestStatus, RpcRequest, RpcResponse, RpcReturnValue};

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

pub struct WsClient {
	pub out: Sender,
	pub request: String,
	pub result: MpscSender<String>,
	pub do_watch: bool,
}

impl Handler for WsClient {
	fn on_open(&mut self, _: Handshake) -> ClientResult<()> {
		debug!("sending request: {:?}", self.request.clone());
		match self.out.send(self.request.clone()) {
			Ok(_) => Ok(()),
			Err(e) => Err(e),
		}
	}
	fn on_message(&mut self, msg: Message) -> ClientResult<()> {
		info!("got message");
		debug!("{}", msg);
		self.result.send(msg.to_string()).unwrap();
		if !self.do_watch {
			self.out.close(CloseCode::Normal).unwrap();
		}
		Ok(())
	}
}

#[derive(Clone)]
pub struct DirectClient {
	url: String,
}

pub trait DirectApi {
	// will remove unit err in refactoring process
	#[allow(clippy::result_unit_err)]
	fn watch(&self, request: String, sender: MpscSender<String>) -> Result<(), ()>;
	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, String>;
}

impl DirectClient {
	pub fn new(url: String) -> Self {
		Self { url }
	}

	/// server connection with only one response
	#[allow(clippy::result_unit_err)]
	pub fn get(&self, request: String) -> Result<String, ()> {
		let url = self.url.clone();
		let (port_in, port_out) = channel();

		info!("[WorkerApi Direct]: Sending request: {:?}", request);
		let client = thread::spawn(move || {
			match connect(url, |out| WsClient {
				out,
				request: request.clone(),
				result: port_in.clone(),
				do_watch: false,
			}) {
				Ok(c) => c,
				Err(_) => {
					error!("Could not connect to direct invoation server");
				},
			}
		});
		client.join().unwrap();

		match port_out.recv() {
			Ok(p) => Ok(p),
			Err(_) => {
				error!("[-] [WorkerApi Direct]: error while handling request, returning");
				Err(())
			},
		}
	}
}

impl DirectApi for DirectClient {
	/// server connection with more than one response
	#[allow(clippy::result_unit_err)]
	fn watch(&self, request: String, sender: MpscSender<String>) -> Result<(), ()> {
		let url = self.url.clone();

		info!("[WorkerApi Direct]: Sending request: {:?}", request);
		thread::spawn(move || {
			match connect(url, |out| WsClient {
				out,
				request: request.clone(),
				result: sender.clone(),
				do_watch: true,
			}) {
				Ok(c) => c,
				Err(_) => {
					error!("Could not connect to direct invoation server");
				},
			}
		});
		Ok(())
	}

	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, String> {
		// compose jsonrpc call
		let method = "author_getShieldingKey".to_owned();
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(method, vec![]);

		let response_str = match Self::get(&self, jsonrpc_call) {
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
	}
}
