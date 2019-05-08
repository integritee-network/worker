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

extern crate substrate_api_client;
extern crate runtime_primitives;
extern crate my_node_runtime;
extern crate parity_codec;
extern crate primitives;
extern crate hex_literal;
extern crate sgx_crypto_helper;
extern crate env_logger;

use std::fs;

use primitive_types::U256;
use parity_codec::{Encode};
use substrate_api_client::{Api};

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

#[macro_use]
extern crate clap;
use clap::App;

use blake2_rfc::blake2s::{blake2s};

pub static RSA_PUB_KEY: &'static str = "./bin/rsa_pubkey.txt";

use substratee_client_example::*;

fn main() {
	let yml = load_yaml!("cli.yml");

	let matches = App::from_yaml(yml).get_matches();
	if let Some(_matches) = matches.subcommand_matches("getcounter") {
		println!("* Getting the counter value from the substraTEE-worker");
		get_counter("Alice");
		return;
	}

	let port = matches.value_of("port").unwrap_or("9944");
	let server = matches.value_of("server").unwrap_or("127.0.0.1");
	let mut api: substrate_api_client::Api = Api::new(format!("ws://{}:{}", server, port));
	api.init();

	// get Alice's free balance
	get_free_balance(&api, "//Alice");

	// get Alice's account nonce
	let mut nonce = get_account_nonce(&api, "//Alice");

	// fund the account of Alice
	fund_account(&api, "//Alice", 1_000_000, nonce, api.genesis_hash.unwrap());

	// transfer from Alice to TEE)
	nonce = get_account_nonce(&api, "//Alice");
	let tee_pub = get_enclave_pub_key();
	transfer_amount(&api, "//Alice", tee_pub ,  U256::from(1000), nonce, api.genesis_hash.unwrap());

	nonce = get_account_nonce(&api, "//Alice");

	// get the public encryption key of the TEE
	let data = fs::read_to_string(RSA_PUB_KEY).expect("Unable to open rsa pubkey file");
	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(&data).unwrap();
	println!("[+] Got RSA public key of TEE = {:?}", rsa_pubkey);

	// generate extrinsic with encrypted payload
	let mut payload_encrypted: Vec<u8> = Vec::new();
	let message = matches.value_of("message").unwrap_or("Alice,42");
	let plaintext = message.as_bytes();
	println!("sending message {:?}", plaintext);
	rsa_pubkey.encrypt_buffer(&plaintext, &mut payload_encrypted).unwrap();
	let xt = compose_extrinsic_substratee_call_worker("//Alice", payload_encrypted, nonce, api.genesis_hash.unwrap());

	// println!("");
	// println!("extrinsic: {:?}", xt);
	let mut _xthex = hex::encode(xt.encode());
	_xthex.insert_str(0, "0x");

	// send and watch extrinsic until finalized
	let tx_hash = api.send_extrinsic(_xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("");

	let act_hash = subscribe_to_call_confirmed(port);

	println!("Expected Hash: {:?}", blake2s(32, &[0; 32], &plaintext).as_bytes());
	println!("Actual Hash: {:?}", act_hash);
}
