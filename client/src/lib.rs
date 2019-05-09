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

extern crate system;

use std::thread;
use std::fs;
use primitive_types::U256;
use std::sync::mpsc::channel;
use ws::{connect, CloseCode};
use node_primitives::{Index,Balance};
use runtime_primitives::generic::Era;
use parity_codec::{Encode, Decode, Compact};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use substrate_api_client::{hexstr_to_u256, hexstr_to_vec};
use my_node_runtime::{
	UncheckedExtrinsic,
	Call,
	SubstraTEEProxyCall,
	BalancesCall,
	Hash,
	Event,
};
use primitives::{
	ed25519,
	hexdisplay::HexDisplay,
	Pair,
	crypto::Ss58Codec,
	blake2_256,
};

pub static RSA_PUB_KEY: &'static str = "./bin/rsa_pubkey.txt";
pub static ECC_PUB_KEY: &'static str = "./bin/ecc_pubkey.txt";

pub fn pair_from_suri(suri: &str, password: Option<&str>) -> ed25519::Pair {
	ed25519::Pair::from_string(suri, password).expect("Invalid phrase")
}

// function to get the free balance of a user
pub fn get_free_balance(api: &substrate_api_client::Api, user: &str) {
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
pub fn get_account_nonce(api: &substrate_api_client::Api, user: &str) -> U256 {
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

// function to get the ED25519 public key from the enclave
pub fn get_enclave_ecc_pub_key() -> ed25519::Public {
	let mut key = [0; 32];
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ecc pubkey file");
	key.copy_from_slice(&ecc_key[..]);
	// println!("\n\n[+] Got ECC public key of TEE = {:?}\n\n", key);

	ed25519::Public::from_raw(key)
}

// function to get the RSA3072 public key from the enclave
pub fn get_enclave_rsa_pub_key() -> Rsa3072PubKey {

	let data = fs::read_to_string(RSA_PUB_KEY).expect("Unable to open rsa pubkey file");
	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(&data).unwrap();
	// println!("[+] Got RSA public key of TEE = {:?}", rsa_pubkey);

	rsa_pubkey
}

// function to get the counter from the substraTEE-worker
pub fn get_counter(user: &'static str)
{
	// Client thread
	let client = thread::spawn(move || {
		connect("ws://127.0.0.1:2019", |out| {
			out.send(format!("{}", user)).unwrap();

			move |msg| {
				println!("Client got message '{}'. ", msg);
				out.close(CloseCode::Normal)
			}

		}).unwrap()
	});
	let _ = client.join();
}

// function to fund an account
pub fn fund_account(api: &substrate_api_client::Api, user: &str, amount: u128, nonce: U256, genesis_hash: Hash) {
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
	println!("[<] Fund completed");
	println!("");
}

// function to compose the extrinsic for a Balance::set_balance call
pub fn extrinsic_fund(from: &str, to: &str, free: u128, reserved: u128, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
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

pub fn transfer_amount(api: &substrate_api_client::Api, from: &str, to: ed25519::Public, amount: U256, nonce: U256, genesis_hash: Hash) {
	println!("");
	println!("[>] Transfer {} from '{}' to '{}'", amount, from, to);

	// build the extrinsic for transfer
	let xt = extrinsic_transfer(from, to, amount, nonce, genesis_hash);

	// encode as hex
	let mut xthex = hex::encode(xt.encode());
	xthex.insert_str(0, "0x");

	// send the extrinsic
	let tx_hash = api.send_extrinsic(xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("[<] Transfer completed");
	println!("");
}

// function to compose the extrinsic for a Balance::transfer call
pub fn extrinsic_transfer(from: &str, to: ed25519::Public, amount: U256, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let signer = pair_from_suri(from, Some(""));

	let era = Era::immortal();
	let amount = Balance::from(amount.low_u128());
	let index = Index::from(index.low_u64());

	let function = Call::Balances(BalancesCall::transfer(to.into(), amount));
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
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

// subscribes to he substratee_proxy events of type CallConfirmed
pub fn subscribe_to_call_confirmed(api: substrate_api_client::Api) -> Vec<u8>{
	let (events_in, events_out) = channel();

	let _eventsubscriber = thread::Builder::new()
		.name("eventsubscriber".to_owned())
		.spawn(move || {
			api.subscribe_events(events_in.clone());
		})
		.unwrap();

	println!("[+] Subscribed, waiting for event...");
	loop {
		let event_str = events_out.recv().unwrap();

		let _unhex = hexstr_to_vec(event_str);
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<system::EventRecord::<Event>>::decode(&mut _er_enc);
		match _events {
			Some(evts) => {
				for evr in &evts {
					match &evr.event {
						Event::substratee_proxy(pe) => {
							match &pe {
								my_node_runtime::substratee_proxy::RawEvent::CallConfirmed(sender, payload) => {
									println!("[+] Received confirm call from {}", sender);
									return payload.to_vec().clone();
								},
								_ => {},
							}
						}
						_ => {},
					}
				}
			}
			_ => {},
		}
	}
}
