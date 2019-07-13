/*
	Copyright 2019 Supercomputing Systems AG

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

extern crate sgx_types;
extern crate ws;

use enclave_api::{get_counter, get_rsa_encryption_pubkey};
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use std::thread;
use ws::{CloseCode, Handler, listen, Message, Result, Sender, Handshake, Error};
use std::str;
use std::sync::mpsc::Sender as ThreadOut;


const MSG_GET_PUB_KEY_WORKER: &str = "get_pub_key_worker";
pub const MSG_MU_RA_PORT: &str = "get_mu_ra_port";

pub fn start_ws_server(eid: sgx_enclave_id_t, addr: String, mu_ra_port: String) {
    // Server WebSocket handler
    struct Server {
        out: Sender,
        eid: sgx_enclave_id_t,
		mu_ra_port: String,
    }

    impl Handler for Server {
        fn on_message(&mut self, msg: Message) -> Result<()> {
            info!("[WS Server] Got message '{}'. ", msg);

			let answer = match &msg.clone().into_text().unwrap()[..] {
				MSG_GET_PUB_KEY_WORKER => get_worker_pub_key(self.eid),
				MSG_MU_RA_PORT => Message::text(self.mu_ra_port.clone()),
				_ => handle_get_counter_msg(self.eid, msg),
			};

            self.out.send(answer)
        }

        fn on_close(&mut self, code: CloseCode, reason: &str) {
            info!("[WS Server] WebSocket closing for ({:?}) {}", code, reason);
        }
    }
    // Server thread
    info!("Starting WebSocket server on {}", addr);
    thread::spawn(move || {
        listen(addr, |out| {
            Server { out, eid, mu_ra_port: mu_ra_port.clone() }
        }).unwrap()
    });
}

fn handle_get_counter_msg(eid: sgx_enclave_id_t, msg: Message) -> Message {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let account = msg.clone().into_data();
	let mut value = 0u32;

	let result = unsafe {
		get_counter(eid,
					&mut retval,
					account.as_ptr(),
					account.len() as u32,
					&mut value)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => { error!("[-] ECALL Enclave failed {}!", result.as_str()) }
	}

	Message::text(format!("Counter of {} = {}", msg, value))
}

fn get_worker_pub_key(eid: sgx_enclave_id_t) -> Message {
	// request the key
	println!();
	println!("*** Ask the public key from the TEE");
	let pubkey_size = 8192;
	let mut pubkey = vec![0u8; pubkey_size as usize];

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_rsa_encryption_pubkey(eid,
								  &mut retval,
								  pubkey.as_mut_ptr(),
								  pubkey_size
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => { error!("[-] ECALL Enclave failed {}!", result.as_str()) }
	}


	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();
	println!("[+] RSA pubkey{:?}", rsa_pubkey);

	let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
	Message::text(rsa_pubkey_json.to_string())
}

pub struct WsClient {
	pub out: Sender,
	pub request: String,
	pub result: ThreadOut<String>
}

impl Handler for WsClient {
	fn on_open(&mut self, _: Handshake) -> Result<()> {

		info!("sending request: {}", self.request);

		match self.out.send(self.request.clone()) {
			Ok(_) => Ok(()),
			Err(e) => return Err(e),
		}
	}
	fn on_message(&mut self, msg: Message) -> Result<()> {
		info!("got message");
		debug!("{}", msg);
		let retstr = msg.as_text().unwrap();

		self.result.send(retstr.to_string()).unwrap();
		self.out.close(CloseCode::Normal).unwrap();
		Ok(())
	}
}
