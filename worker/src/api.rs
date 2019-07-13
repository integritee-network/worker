use websocket::client::WsClient;
use websocket::requests::*;
use std::sync::mpsc::channel;
use std::thread;
use ws::connect;
use log::*;


pub struct Api {
	url: String,
}

impl Api {
	pub fn new(url: String) -> Api {
		Api {
			url: format!("ws://{}",  url),
		}
	}

	pub fn get_pub_key(&self) -> Result<String, ()> {

		let url = self.url.clone();
		let (port_in, port_out) = channel();
		let client = thread::spawn(move || {
			match connect(url, |out| {
				WsClient {
					out: out,
					request: MSG_MU_RA_PORT.to_string(),
					result: port_in.clone()
				}
			}) {
				Ok(c) => c,
				Err(_) => {
					error!("Could not connect to worker");
					return;
				}
			}
		});
		client.join().unwrap();

		match port_out.recv() {
			Ok(p) => Ok(p),
			Err(_) => {
				error!("[-] Could not connect to worker, returning");
				return Err(())
			},
		}
	}
}
