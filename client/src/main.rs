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

#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate hex_literal;
extern crate log;
extern crate my_node_runtime;
extern crate codec;
extern crate primitives;
extern crate runtime_primitives;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate substrate_api_client;

use blake2_rfc::blake2s::blake2s;
use clap::App;
use codec::Encode;
use primitive_types::U256;
use primitives::Pair;
use sgx_types::*;
use substrate_api_client::Api;

use substratee_client::*;
use substratee_node_calls::{get_worker_amount, get_worker_info};
use substratee_worker_api::Api as WorkerApi;

const WASM_FILE: &str = "worker_enclave.compact.wasm";

fn main() {
	// message structure
	#[derive(Debug, Serialize, Deserialize)]
	struct Message {
		account: String,
		amount: u32,
		sha256: sgx_sha256_hash_t
	}

	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("node-port").unwrap_or("9944");
	let server = matches.value_of("node-server").unwrap_or("127.0.0.1");
	let mut api: substrate_api_client::Api = Api::new(format!("ws://{}:{}", server, port));

	println!("*** Getting the amount of the registered workers");
	let worker = match get_worker_amount(&api) {
		0 => {
			println!("No worker in registry, returning...");
			return;
		}
		x => {
			println!("[<] Found {}  workers\n", x);
			println!("[>] Getting the first worker's from the substraTEE-node");
			get_worker_info(&api, 0)
		}
	};
	println!("[<] Got first worker's coordinates:");
	println!("    W1's public key : {:?}", worker.pubkey.to_string());
	println!("    W1's url: {:?}\n", worker.url);

	let worker_api = WorkerApi::new(worker.url.clone());

	if let Some(_matches) = matches.subcommand_matches("getcounter") {
		let user = pair_from_suri("//Alice", Some(""));
		println!("*** Getting the counter value of //Alice = {:?} from the substraTEE-worker", user.public().to_string());
		let sign = user.sign(user.public().as_slice());
		let value = worker_api.get_counter(user.public(), sign).unwrap();

		println!("[<] Received MSG: {}", value);
		return;
	}

	let wasm_path = matches.value_of("wasm-path").unwrap_or(WASM_FILE);
	let hash_hex = get_wasm_hash(wasm_path);
	println!("[>] Calculating  WASM hash of {:?}", wasm_path);
	println!("[<] WASM Hash: {:?}\n", hash_hex[0]);
	let hash = hex::decode(hash_hex[0].clone()).unwrap();
	let sha256: sgx_sha256_hash_t = slice_to_hash(&hash);

	// get Alice's free balance
	get_free_balance(&api, "//Alice");

	// get Alice's account nonce
	let mut nonce = get_account_nonce(&api, "//Alice");

	// fund the account of Alice
	fund_account(&api, "//Alice", 1_000_000, nonce, api.genesis_hash);

	// transfer from Alice to TEE
	nonce = get_account_nonce(&api, "//Alice");
	transfer_amount(&api, "//Alice", worker.pubkey.clone(), U256::from(1000), nonce, api.genesis_hash);

	// compose extrinsic with encrypted payload
	println!("[>] Get the encryption key from W1 (={})", worker.pubkey.to_string());
	let rsa_pubkey = worker_api.get_rsa_pubkey().unwrap();
	println!("[<] Got worker shielding key {:?}\n", rsa_pubkey);

	let account = user_to_pubkey("//Alice").to_string();
	println!("[+] //Alice's Pubkey: {}\n", account);
	let amount = value_t!(matches.value_of("amount"), u32).unwrap_or(42);
	let message = Message { account, amount, sha256 };
	let plaintext = serde_json::to_vec(&message).unwrap();
	let mut payload_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&plaintext, &mut payload_encrypted).unwrap();
	println!("[>] Sending message '{:?}' to substraTEE-worker.\n", message);
	nonce = get_account_nonce(&api, "//Alice");
	let xt = compose_extrinsic!(
        api.clone(),
        "SubstraTEERegistry",
        "call_worker",
		payload_encrypted
    );

	// send and watch extrinsic until finalized
	let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("[<] Message sent successfully");
	println!();

	// subsribe to callConfirmed event
	println!("[>] Subscribe to callConfirmed event");
	let act_hash = subscribe_to_call_confirmed(api);
	println!("[<] callConfirmed event received");
	println!("[+] Expected Hash: {:?}", blake2s(32, &[0; 32], &plaintext).as_bytes());
	println!("[+] Actual Hash:   {:?}", act_hash);
}
