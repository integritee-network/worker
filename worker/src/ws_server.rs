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

use std::str;
use std::thread;

use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use ws::{CloseCode, Handler, listen, Message, Result, Sender};
use primitive_types::U256;
//use enclave_api::{get_counter, get_rsa_encryption_pubkey};
use enclave_api::{get_rsa_encryption_pubkey, get_state};
use substratee_worker_api::requests::*;

pub fn start_ws_server(eid: sgx_enclave_id_t, addr: String, mu_ra_port: String) {
	// Server WebSocket handler
	struct Server {
		out: Sender,
		eid: sgx_enclave_id_t,
		mu_ra_port: String,
	}

	impl Handler for Server {
		fn on_message(&mut self, msg: Message) -> Result<()> {
			info!("     [WS Server] Got message '{}'. ", msg);

			let msg_txt = msg.into_text().unwrap();
			let args: Vec<&str> = msg_txt.split("::").collect();

			let answer = match args[0] {
				MSG_GET_PUB_KEY_WORKER => get_worker_pub_key(self.eid),
				MSG_GET_MU_RA_PORT => Message::text(self.mu_ra_port.clone()),
				MSG_GET_STF_STATE => handle_get_stf_state_msg(self.eid, args[1]),
				_ => Message::text("[WS Server]: unrecognized msg pattern"),
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

fn handle_get_stf_state_msg(eid: sgx_enclave_id_t, getter_str: &str) -> Message {

	info!("     [WS Server] Getting STF state");

	// FIXME: its good to check the signature here, but it should also be verified inside the enclave again!
	let getter_vec = hex::decode(getter_str).unwrap();
	let mut retval = sgx_status_t::SGX_SUCCESS;

	// FIXME: will not always be u128!!
	let value_size = 16; //u128
	let mut value: Vec<u8> = vec![0u8; value_size as usize];

	let result = unsafe {
		get_state(eid,
					&mut retval,
					getter_vec.as_ptr(),
					getter_vec.len() as u32,
					value.as_mut_ptr(),
					value_size as u32
					)
	};
	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => { error!("[-] ECALL Enclave failed {}!", result.as_str()) }
	}
	debug!("get_state result: {:?}", value);
	//let val = hexstr_to_u256(String::from_utf8(value).unwrap()).unwrap();
	let val = U256::from_little_endian(&value);
	println!("decoded value value: {}", val);

	Message::text(format!("State is {}", val))
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
	println!("     [WS Server] RSA pubkey {:?}\n", rsa_pubkey);

	let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
	Message::text(rsa_pubkey_json.to_string())
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn get_counter_signature_checking_works() {

		let user = ed25519::Pair::from_string("//Alice", Some("")).expect("Invalid phrase");
		let sign = user.sign(user.public().as_slice());

		let sign_str = serde_json::to_string::<[u8]>(sign.as_ref()).unwrap();
		let acc_str = serde_json::to_string(&user.public()).unwrap();

		let request = format!("{}::{}::{}", MSG_GET_COUNTER, acc_str, sign_str);
		let mut args: Vec<&str> = request.split("::").collect();

		let mut sig_vec:  Vec<u8> = serde_json::from_str(args[2]).unwrap();
		let mut sig_arr = [0u8; 64];
		sig_arr.clone_from_slice(&sig_vec);

		let pubkey: ed25519::Public = serde_json::from_str(&mut args[1]).unwrap();
		let sign: ed25519::Signature = ed25519::Signature::from_raw(sig_arr);

		assert!(ed25519::Pair::verify(&sign, pubkey.clone().as_slice(), &pubkey.clone()));
	}
}
