///! Interface for direct access to a workers rpc.
///
/// This should be replaced with the `jsonrpsee::WsClient`. It is async an removes a lot of
/// boilerplate code. Example usage in worker/worker.rs.
///
use codec::Decode;
use log::*;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::{
	sync::mpsc::{channel, Sender as MpscSender},
	thread,
};
use url;
use ws::{
	connect, util::TcpStream, CloseCode, Handler, Handshake, Message, Result as ClientResult,
	Sender,
};

use itp_types::{DirectRequestStatus, RpcRequest, RpcResponse, RpcReturnValue};

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
		info!("sending result to MpscSender..");
		self.result.send(msg.to_string()).unwrap();
		if !self.do_watch {
			info!("do_watch is false, closing connection");
			self.out.close(CloseCode::Normal).unwrap();
			info!("connection is closed");
		}
		info!("on_message successful, returning");
		Ok(())
	}

	/// we are overriding the `upgrade_ssl_client` method in order to disable hostname verification
	/// this is taken from https://github.com/housleyjk/ws-rs/blob/master/examples/unsafe-ssl-client.rs
	/// TODO: hostname verification should probably be enabled again for production?
	fn upgrade_ssl_client(
		&mut self,
		sock: TcpStream,
		_: &url::Url,
	) -> ws::Result<SslStream<TcpStream>> {
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

		info!("[WorkerApi Direct]: (get) Sending request: {:?}", request);
		let client = thread::spawn(move || {
			match connect(url, |out| WsClient {
				out,
				request: request.clone(),
				result: port_in.clone(),
				do_watch: false,
			}) {
				Ok(c) => c,
				Err(_) => {
					error!("Could not connect to direct invocation server");
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

		info!("[WorkerApi Direct]: (watch) Sending request: {:?}", request);
		thread::spawn(move || {
			info!("attempting to connect to RPC");
			match connect(url, |out| WsClient {
				out,
				request: request.clone(),
				result: sender.clone(),
				do_watch: true,
			}) {
				Ok(c) => {
					info!("connect was successful");
					c
				},
				Err(_) => {
					error!("Could not connect to direct invocation server");
				},
			}
		});
		Ok(())
	}

	fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, String> {
		// compose jsonrpc call
		let method = "author_getShieldingKey".to_owned();
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
	}
}
