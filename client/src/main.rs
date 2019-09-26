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
use primitives::{Pair, Public, crypto::Ss58Codec};
use sgx_types::*;
use substrate_api_client::{Api, compose_extrinsic, extrinsic,
	utils::{hexstr_to_vec, hexstr_to_u256},
	crypto::{AccountKey, CryptoKind},
	extrinsic::{balances::transfer, xt_primitives::GenericAddress},
	};

use substratee_client::{get_account_nonce, subscribe_to_call_confirmed, pair_from_suri_sr, transfer_amount, fund_account, get_free_balance, pair_from_suri};
use substratee_node_calls::{get_worker_amount, get_worker_info};
use substratee_worker_api::Api as WorkerApi;
use substratee_stf::TrustedCall;
use log::*;

use runtime_primitives::{AnySignature, traits::Verify};
type AccountId = <AnySignature as Verify>::Signer;

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

	let port = matches.value_of("node-ws-port").unwrap_or("9944");
	let server = matches.value_of("node-addr").unwrap_or("127.0.0.1");
	
	info!("initializing ws api to node");
	let alice = primitives::sr25519::Pair::from_string("//Alice", None).unwrap();
	let alicekey = AccountKey::Sr(alice.clone());
	info!("use Alice account as signer = {}", alice.public().to_ss58check());
	let mut api: substrate_api_client::Api = Api::new(format!("ws://{}:{}", server, port))
	   	.set_signer(alicekey.clone());

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
	info!("getting free_balance for Alice");
	// get Alice's free balance

	let result_str = api.get_storage("Balances", "FreeBalance", Some(AccountId::from(alice.public()).encode())).unwrap();
    let funds = hexstr_to_u256(result_str).unwrap();
	info!("Alice free balance = {:?}", funds);
    let result_str = api.get_storage("System", "AccountNonce", Some(AccountId::from(alice.public()).encode())).unwrap();
    let result = hexstr_to_u256(result_str).unwrap();
    println!("[+] Alice's Account Nonce is {}", result.low_u32());

	// compose extrinsic with encrypted payload
	println!("[>] Get the shielding key from W1 (={})", worker.pubkey.to_string());
	let rsa_pubkey = worker_api.get_rsa_pubkey().unwrap();
	println!("[<] Got worker shielding key {:?}\n", rsa_pubkey);

	let alice_incognito_pair = pair_from_suri_sr("//AliceIncognito", Some(""));
	println!("[+] //Alice's Incognito Pubkey: {}\n", alice_incognito_pair.public());

	let call = TrustedCall::balance_set_balance(alice_incognito_pair.public(), 33,44);
	let call_encoded = call.encode();
	let mut call_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&call_encoded, &mut call_encrypted).unwrap();
	
	println!("[>] Sending message to substraTEE-worker.\n");
	//nonce = get_account_nonce(&api, "//Alice");
	let xt = compose_extrinsic!(
        api.clone(),
        "SubstraTEERegistry",
        "call_worker",
		call_encrypted.clone()
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
	println!("[+] Expected Hash: {:?}", blake2s(32, &[0; 32], &call_encrypted).as_bytes());
	println!("[+] Actual Hash:   {:?}", act_hash);
}
