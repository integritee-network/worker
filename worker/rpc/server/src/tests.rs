use log::info;

use super::*;
use soketto::handshake;
use serde_json::Value as JsonValue;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use futures_util::io::{BufReader, BufWriter};
use tokio::net::TcpStream;

fn init() {
	let _ = env_logger::builder().is_test(true).try_init();
}

struct WsTestClient {
	tx: soketto::Sender<BufReader<BufWriter<Compat<TcpStream>>>>,
	rx: soketto::Receiver<BufReader<BufWriter<Compat<TcpStream>>>>,
}

type Error = Box<dyn std::error::Error>;

impl WsTestClient {
	pub async fn new(url: SocketAddr) -> Result<Self, Error> {
		let socket = TcpStream::connect(url).await?;
		let mut client = handshake::Client::new(BufReader::new(BufWriter::new(socket.compat())), "test-client", "/");
		match client.handshake().await {
			Ok(handshake::ServerResponse::Accepted { .. }) => {
				let (tx, rx) = client.into_builder().finish();
				Ok(Self { tx, rx })
			}
			r => Err(format!("WebSocketHandshake failed: {:?}", r).into()),
		}
	}

	pub async fn send_request_text(&mut self, msg: impl AsRef<str>) -> Result<String, Error> {
		self.tx.send_text(msg).await?;
		self.tx.flush().await?;
		let mut data = Vec::new();
		self.rx.receive_data(&mut data).await?;
		String::from_utf8(data).map_err(Into::into)
	}
}

pub fn ok_response(result: JsonValue, id: u32) -> String {
	format!(r#"{{"jsonrpc":"2.0","result":{},"id":{}}}"#, result, id)
}

#[tokio::test]
async fn test_client_calls() {
	init();
	let addr = run_server("127.0.0.1:0").await.unwrap();
	info!("ServerAddress: {:?}", addr);

	let mut client = WsTestClient::new(addr).await.unwrap();

	let req = format!(r#"{{"jsonrpc":"2.0","method":"author_importBlock","id":{}}}"#, 1);
	let res = client.send_request_text(req).await.unwrap();
	assert_eq!(res, ok_response(JsonValue::String("Hello".into()), 1));
}