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

use log::info;
use std::thread;
use std::fs;
use primitive_types::{U256, H256};
use std::sync::mpsc::channel;
use ws::{connect, CloseCode, Message};
use runtime_primitives::generic::Era;
use parity_codec::{Encode, Decode, Compact};
use substrate_api_client::{Api, hexstr_to_u256, hexstr_to_vec};
use my_node_runtime::{
	UncheckedExtrinsic,
	Call,
	SubstraTEERegistryCall,
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

pub static ECC_PUB_KEY: &str = "./bin/ecc_pubkey.txt";

pub fn pair_from_suri(suri: &str, password: Option<&str>) -> ed25519::Pair {
	ed25519::Pair::from_string(suri, password).expect("Invalid phrase")
}

pub fn user_to_pubkey(user: &str) -> ed25519::Public {
	ed25519::Public::from_string(user).ok()
	.or_else(|| ed25519::Pair::from_string(user, Some("")).ok().map(|p| p.public()))
	.expect("Invalid 'to' URI; expecting either a secret URI or a public URI.")
}

pub fn get_from_storage(api: &Api, user: &str, category: &str, item: &str) -> U256 {
	println!("[>] Get {}'s {}", user, item);

	let accountid = user_to_pubkey(user);
	let result_str = api.get_storage(category, item, Some(accountid.encode())).unwrap();
	let result = hexstr_to_u256(result_str);
	println!("[<] {}'s {} is {}", user, item, result);
	println!();
	result
}

// function to get the free balance of a user
pub fn get_free_balance(api: &Api, user: &str) -> U256 {
	get_from_storage(api, user, "Balances", "FreeBalance")
}

// function to get the account nonce of a user
pub fn get_account_nonce(api: &Api, user: &str) -> U256 {
	get_from_storage(api, user, "System", "AccountNonce")
}

// function to get the ED25519 public key from the enclave
pub fn get_enclave_ecc_pub_key() -> ed25519::Public {
	let mut key = [0; 32];
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ECC public key file");
	key.copy_from_slice(&ecc_key[..]);
	info!("[+] Got ECC public key of TEE = {:?}\n\n", key);

	ed25519::Public::from_raw(key)
}

// function to get the counter from the substraTEE-worker
pub fn get_counter(user: &'static str) {
	// Client thread
	let client = thread::spawn(move || {
		connect("ws://127.0.0.1:2019", |out| {
			out.send(user).unwrap();

			move |msg| {
				println!("[+] Client got message '{}'. ", msg);
				println!();
				out.close(CloseCode::Normal)
			}

		}).unwrap()
	});
	let _ = client.join();
}

// function to get the counter from the substraTEE-worker
pub fn get_worker_encryption_key() {
	// Client thread
	let client = thread::spawn(move || {
		 connect("ws://127.0.0.1:2019", |out| {
			out.send("get_pub_key_worker").unwrap();

			move |msg: Message| {
				println!("[+] Client got encryption key '{}'. ", &msg);
				println!();
				out.close(CloseCode::Normal)
			}
		}).unwrap();
	});
	client.join().unwrap();
}

// function to fund an account
pub fn fund_account(api: &Api, user: &str, amount: u128, nonce: U256, genesis_hash: Hash) {
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
	println!();
}

pub fn compose_extrinsic(from: &str, function: Call, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let signer = pair_from_suri(from, Some(""));
	let era = Era::immortal();

	let index = index.low_u64();
	let raw_payload = (Compact(index), function, era, genesis_hash);

	let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		signer.sign(&blake2_256(payload)[..])
	} else {
		info!("signing {}", HexDisplay::from(&payload));
		signer.sign(payload)
	});

	UncheckedExtrinsic::new_signed(
		index,
		raw_payload.1,
		signer.public().into(),
		signature,
		era,
	)
}

// function to compose the extrinsic for a Balance::set_balance call
pub fn extrinsic_fund(from: &str, to: &str, free: u128, reserved: u128, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let to = user_to_pubkey(to);
	let function = Call::Balances(BalancesCall::set_balance(to.into(), free, reserved));
	compose_extrinsic(from, function, index, genesis_hash)
}

pub fn transfer_amount(api: &Api, from: &str, to: ed25519::Public, amount: U256, nonce: U256, genesis_hash: Hash) {
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
	println!();
}

// function to compose the extrinsic for a Balance::transfer call
pub fn extrinsic_transfer(from: &str, to: ed25519::Public, amount: U256, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let amount = amount.low_u128();
	let function = Call::Balances(BalancesCall::transfer(to.into(), amount));
	compose_extrinsic(from, function, index, genesis_hash)
}

// function to compose the extrinsic for a SubstraTEERegistry::call_worker call
pub fn compose_extrinsic_substratee_call_worker(from: &str, payload_encrypted: Vec<u8>, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let payload_encrypted_str = payload_encrypted;
	let function = Call::SubstraTEERegistry(SubstraTEERegistryCall::call_worker(payload_encrypted_str));
	compose_extrinsic(from, function, index, genesis_hash)
}

// subscribes to he substratee_registry events of type CallConfirmed
pub fn subscribe_to_call_confirmed(api: Api) -> Vec<u8>{
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
		let _events = Vec::<system::EventRecord::<Event, Hash>>::decode(&mut _er_enc);
		if let Some(evts) = _events {
			for evr in &evts {
				if let Event::substratee_registry(pe) = &evr.event {
					if let my_node_runtime::substratee_registry::RawEvent::CallConfirmed(sender, payload) = &pe {
						println!("[+] Received confirm call from {}", sender);
						return payload.to_vec().clone();
					}
				}
			}
		}
	}
}

// convert from vec to array
pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];
	let bytes = &bytes[..array.len()]; // panics if not enough data
	array.copy_from_slice(bytes);
	array
}

// Tests require a running node and running worker
#[cfg(test)]
mod tests {
	use substrate_api_client::{Api};

	use super::*;

	#[test]
	fn get_worker_encryption_key_should_work() {
		get_worker_encryption_key();
	}
}
