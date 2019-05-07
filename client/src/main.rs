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

use std::fs;
use my_node_runtime::{
	UncheckedExtrinsic,
	Call,
	SubstraTEEProxyCall,
	BalancesCall,
	Hash,
};

use primitive_types::U256;
use node_primitives::{Index,Balance};
use parity_codec::{Encode, Compact};
use runtime_primitives::generic::Era;
use substrate_api_client::{Api,hexstr_to_u256};

use primitives::{
	ed25519,
	hexdisplay::HexDisplay,
	Pair,
	crypto::Ss58Codec,
	blake2_256,
};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

#[macro_use]
extern crate clap;
use clap::App;

pub static RSA_PUB_KEY: &'static str = "./bin/rsa_pubkey.txt";
pub static ECC_PUB_KEY: &'static str = "./bin/ecc_pubkey.txt";

fn pair_from_suri(suri: &str, password: Option<&str>) -> ed25519::Pair {
	ed25519::Pair::from_string(suri, password).expect("Invalid phrase")
}

// function to get the free balance of a user
fn get_free_balance(api: &substrate_api_client::Api, user: &str) {
	println!("");
	println!("[>] Get {}'s free balance", user);

	let accountid = ed25519::Public::from_string(user).ok().or_else(||
			ed25519::Pair::from_string(user, Some("")).ok().map(|p| p.public())
		).expect("Invalid 'to' URI; expecting either a secret URI or a public URI.");

	let result_str = api.get_storage("Balances", "FreeBalance", Some(accountid.encode())).unwrap();
    let result = hexstr_to_u256(result_str);

	println!("[<] {}'s free balance is {}", user, result);
	println!("");
}

// function to get the account nonce of a user
fn get_account_nonce(api: &substrate_api_client::Api, user: &str) -> U256 {
	println!("");
	println!("[>] Get {}'s account nonce", user);

	let accountid = ed25519::Public::from_string(user).ok().or_else(||
			ed25519::Pair::from_string(user, Some("")).ok().map(|p| p.public())
		).expect("Invalid 'to' URI; expecting either a secret URI or a public URI.");

	let result_str = api.get_storage("System", "AccountNonce", Some(accountid.encode())).unwrap();
	let nonce = hexstr_to_u256(result_str);
	println!("[<] {}'s account nonce is {}", user, nonce);
	println!("");
	nonce
}

fn main() {
	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();
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

	// transfer from Alice to Bob (= TEE)
	nonce = get_account_nonce(&api, "//Alice");

	transfer_amount(&api, "//Alice", "//Bob", U256::from(1000), nonce, api.genesis_hash.unwrap());
	extrinsic_tranfer_to_enclave("//Alice", U256::from(1000), nonce, api.genesis_hash.unwrap());
	// get the new nonce of Alice
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
}

fn fund_account(api: &substrate_api_client::Api, user: &str, amount: u128, nonce: U256, genesis_hash: Hash) {
	println!("");
	println!("[>] Fund {}'s account with {}", user, amount);

	// build the extrinsic for funding
	let xt = extrinsic_fund(user, user, amount, amount, nonce, genesis_hash);

	// encode as hex
	let mut xthex = hex::encode(xt.encode());
	xthex.insert_str(0, "0x");

	// send the extrinsic
	let tx_hash = api.send_extrinsic(xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("");
}

// function to compose the extrinsic for a Balance::set_balance call
fn extrinsic_fund(from: &str, to: &str, free: u128, reserved: u128, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let signer = pair_from_suri(from, Some(""));

	let to = ed25519::Public::from_string(to).ok().or_else(||
			ed25519::Pair::from_string(to, Some("")).ok().map(|p| p.public())
		).expect("Invalid 'to' URI; expecting either a secret URI or a public URI.");

	let era = Era::immortal();
	let index = Index::from(index.low_u64());

	let function = Call::Balances(BalancesCall::set_balance(to.into(), free, reserved));
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
		println!("signing {}", HexDisplay::from(&payload));
		signer.sign(payload)
	});

	UncheckedExtrinsic::new_signed(
		index,
		raw_payload.1,
		signer.public().into(),
		signature.into(),
		era,
	)
}

fn transfer_amount(api: &substrate_api_client::Api, from: &str, to: &str, amount: U256, nonce: U256, genesis_hash: Hash) {
	println!("");
	println!("[>] Transfer {} from {} to {}", amount, from, to);

	// build the extrinsic for transfer
	let xt = extrinsic_transfer(from, to, amount, nonce, genesis_hash);

	// encode as hex
	let mut xthex = hex::encode(xt.encode());
	xthex.insert_str(0, "0x");

	// send the extrinsic
	let tx_hash = api.send_extrinsic(xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("");
}

// function to compose the extrinsic for a Balance::transfer call
fn extrinsic_transfer(from: &str, to: &str, amount: U256, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let signer = pair_from_suri(from, Some(""));

	let to = ed25519::Public::from_string(to).ok().or_else(||
			ed25519::Pair::from_string(to, Some("")).ok().map(|p| p.public())
		).expect("Invalid 'to' URI; expecting either a secret URI or a public URI.");

	let era = Era::immortal();
	let amount = Balance::from(amount.low_u128());
	let index = Index::from(index.low_u64());

	let function = Call::Balances(BalancesCall::transfer(to.into(), amount));
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
		println!("signing {}", HexDisplay::from(&payload));
		signer.sign(payload)
	});

	UncheckedExtrinsic::new_signed(
		index,
		raw_payload.1,
		signer.public().into(),
		signature.into(),
		era,
	)
}

// function to compose the extrinsic for a SubstraTEEProxy::call_worker call
pub fn compose_extrinsic_substratee_call_worker(sender: &str, payload_encrypted: Vec<u8>, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let signer = pair_from_suri(sender, Some(""));
	let era = Era::immortal();

	// let payload_encrypted_str = payload_encrypted.as_bytes().to_vec();
	let payload_encrypted_str = payload_encrypted;
	let function = Call::SubstraTEEProxy(SubstraTEEProxyCall::call_worker(payload_encrypted_str));

	let index = Index::from(index.low_u64());
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
		println!("");
		println!("signing {}", HexDisplay::from(&payload));
		signer.sign(payload)
	});

	//let () = signature;
	//let sign = AnySignature::from(signature);

	UncheckedExtrinsic::new_signed(
		index,
		raw_payload.1,
		signer.public().into(),
		signature.into(),
		era,
	)
}

// function to compose the extrinsic for a Balance::transfer call
fn extrinsic_tranfer_to_enclave(from: &str, amount: U256, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	println!("\n Transfer from {} to Enclave\n", from);
	let signer = pair_from_suri(from, Some(""));

	let mut key = [0; 32];
		// get the public signing key of the TEE
	let mut ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ecc pubkey file");
	key.copy_from_slice(&ecc_key[..]);
	println!("\n\n[+] Got ECC public key of TEE = {:?}\n\n", key);

	let to = ed25519::Public::from_raw(key);
	println!("\n\n[+] Got primitives key = {:?}\n\n", to.encode());


	let era = Era::immortal();
	let amount = Balance::from(amount.low_u128());
	let index = Index::from(index.low_u64());

	let function = Call::Balances(BalancesCall::transfer(to.into(), amount));
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
		println!("signing {}", HexDisplay::from(&payload));
		signer.sign(payload)
	});

	UncheckedExtrinsic::new_signed(
		index,
		raw_payload.1,
		signer.public().into(),
		signature.into(),
		era,
	)
}

