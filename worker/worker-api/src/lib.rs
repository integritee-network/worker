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

extern crate log;
extern crate primitives;
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate ws;
extern crate substratee_stf;
extern crate codec;

use client::WsClient;
use log::*;
use requests::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use std::sync::mpsc::channel;
use std::thread;
use ws::connect;
use primitives::ed25519;
use substratee_stf::TrustedGetter;
use codec::Encode;

pub mod client;
pub mod requests;

#[derive(Clone)]
pub struct Api {
	url: String,
}

impl Api {
	pub fn new(url: String) -> Api {
		Api {
			url: format!("ws://{}", url),
		}
	}

	pub fn get_mu_ra_port(&self) -> Result<String, ()> {
		Self::get(&self, MSG_GET_MU_RA_PORT)
	}

	pub fn get_rsa_pubkey(&self) -> Result<Rsa3072PubKey, ()> {
		let keystr = Self::get(&self, MSG_GET_PUB_KEY_WORKER)?;

		let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(&keystr).unwrap();
		info!("[+] Got RSA public key of TEE = {:?}", rsa_pubkey);

		Ok(rsa_pubkey)
	}

	pub fn get_stf_state(&self, getter: TrustedGetter) -> Result<String, ()> {
		let getter_str = hex::encode(getter.encode());
		let request = format!("{}::{}", MSG_GET_STF_STATE, getter_str);
		Self::get(&self, &request)
	}

	fn get(&self, request: &str) -> Result<String, ()> {
		let url = self.url.clone();
		let req = request.to_string().clone();
		let (port_in, port_out) = channel();

		info!("[Worker Api]: Sending request: {}", req);
		let client = thread::spawn(move || {
			match connect(url, |out| {
				WsClient {
					out,
					request: req.clone(),
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
				error!("[-] [WorkerApi]: error while handling request, returning");
				Err(())
			},
		}
	}
}
