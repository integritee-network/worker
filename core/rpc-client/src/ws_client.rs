///! Websocket client implementation to access the direct-rpc-server running inside an enclave.
///
/// This should be replaced with the `jsonrpsee::WsClient`as soon as available in no-std:
/// https://github.com/paritytech/jsonrpsee/issues/1
use log::*;
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use std::sync::mpsc::Sender as MpscSender;
use url;
use ws::{connect, util::TcpStream, CloseCode, Handler, Handshake, Message, Result, Sender};

#[derive(Clone)]
pub struct WsClient {
	pub out: Sender,
	pub request: String,
	pub result: MpscSender<String>,
	pub do_watch: bool,
}

impl WsClient {
	pub fn new(
		out: Sender,
		request: String,
		result: MpscSender<String>,
		do_watch: bool,
	) -> WsClient {
		WsClient { out, request, result, do_watch }
	}

	pub fn connect(
		url: &str,
		request: &str,
		result: &MpscSender<String>,
		do_watch: bool,
	) -> Result<()> {
		connect(url.to_string(), |out| {
			WsClient::new(out, request.to_string(), result.clone(), do_watch)
		})
	}
}

impl Handler for WsClient {
	fn on_open(&mut self, _: Handshake) -> Result<()> {
		debug!("sending request: {:?}", self.request.clone());
		match self.out.send(self.request.clone()) {
			Ok(_) => Ok(()),
			Err(e) => Err(e),
		}
	}

	fn on_message(&mut self, msg: Message) -> Result<()> {
		debug!("got message");
		debug!("{}", msg);
		debug!("sending result to MpscSender..");
		self.result.send(msg.to_string()).unwrap();
		if !self.do_watch {
			debug!("do_watch is false, closing connection");
			self.out.close(CloseCode::Normal).unwrap();
			debug!("connection is closed");
		}
		debug!("on_message successful, returning");
		Ok(())
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
