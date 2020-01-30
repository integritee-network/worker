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

use std::process::Command;
use std::sync::mpsc::channel;
use std::thread;

use blake2_rfc::blake2s::blake2s;
use codec::{Decode, Encode};
use log::*;
use log::info;
use my_node_runtime::{
	Event,
	Hash,
};
use primitive_types::U256;
use primitives::{
	crypto::{AccountId32, Pair, Ss58Codec},
	ed25519, sr25519,
};
use runtime_primitives::MultiSignature;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use substrate_api_client::{Api, compose_extrinsic,
						   utils::{hexstr_to_u256, hexstr_to_vec},
};

use substratee_stf::{TrustedCall, TrustedOperation};
use substratee_worker_api::Api as WorkerApi;

// FIXME: most of these functions are redundant with substrate-api-client
// but first resolve this: https://github.com/scs/substrate-api-client/issues/27
pub static ECC_PUB_KEY: &str = "./bin/ecc_pubkey.txt";

pub fn pair_from_suri(suri: &str, password: Option<&str>) -> ed25519::Pair {
	ed25519::Pair::from_string(suri, password).expect("Invalid phrase")
}

pub fn pair_from_suri_sr(suri: &str, password: Option<&str>) -> sr25519::Pair {
	sr25519::Pair::from_string(suri, password).expect("Invalid phrase")
}

pub fn user_to_pubkey(user: &str) -> ed25519::Public {
	ed25519::Public::from_string(user).ok()
	.or_else(|| ed25519::Pair::from_string(user, Some("")).ok().map(|p| p.public()))
	.expect("Invalid 'to' URI; expecting either a secret URI or a public URI.")
}

pub fn get_from_storage<P: Pair>(api: &Api<P>, user: &str, category: &str, item: &str) -> U256
where
	MultiSignature: From<P::Signature>,
{
	println!("[>] Get {}'s {}", user, item);

	let accountid = user_to_pubkey(user);
	let result_str = api.get_storage(category, item, Some(accountid.encode())).unwrap();
	let result = hexstr_to_u256(result_str).unwrap();
	println!("[<] {}'s {} is {}", user, item, result);
	println!();
	result
}

// function to get the free balance of a user
pub fn get_free_balance<P: Pair>(api: &Api<P>, user: &str) -> U256
where
	MultiSignature: From<P::Signature>,
{
	get_from_storage(api, user, "Balances", "FreeBalance")
}

// function to get the account nonce of a user
pub fn get_account_nonce<P: Pair>(api: &Api<P>, user: &str) -> U256
where
	MultiSignature: From<P::Signature>
{
	get_from_storage(api, user, "System", "AccountNonce")
}

// function to fund an account
pub fn fund_account<P: Pair>(api: &Api<P>, user: &str, amount: u128)
where
	MultiSignature: From<P::Signature>
{
	println!("[>] Fund {}'s account with {}", user, amount);

	let acc = AccountId32::from(*user_to_pubkey(user).as_array_ref());

	let xt = compose_extrinsic!(
        api.clone(),
        "Balances",
        "set_balance",
        GenericAddress::from(acc),
        Compact(amount),
		Compact(amount)
    );
	let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();

	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("[<] Fund completed");
	println!();
}

pub fn transfer_amount<P: Pair>(api: &Api<P>, from: &str, to: ed25519::Public, amount: U256)
where
	MultiSignature: From<P::Signature>
{
	println!("[>] Transfer {} from '{}' to '{}'", amount, from, to);

	// build the extrinsic for transfer
	let xt = compose_extrinsic!(
        api.clone(),
        "Balances",
        "transfer",
        GenericAddress::from(AccountId32::from(*to.as_array_ref())),
        Compact(amount.low_u128())
    );

	// send the extrinsic
	let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("[<] Transfer completed");
	println!();
}

// subscribes to he substratee_registry events of type CallConfirmed
pub fn subscribe_to_call_confirmed<P: Pair>(api: Api<P>) -> Vec<u8>
where
	MultiSignature: From<P::Signature>
{
	let (events_in, events_out) = channel();

	let _eventsubscriber = thread::Builder::new()
		.name("eventsubscriber".to_owned())
		.spawn(move || {
			api.subscribe_events(events_in.clone());
		})
		.unwrap();

	println!("[+] Subscribed, waiting for event...\n");
	loop {
		let event_str = events_out.recv().unwrap();

		let _unhex = hexstr_to_vec(event_str).unwrap();
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<system::EventRecord::<Event, Hash>>::decode(&mut _er_enc);
		if let Ok(evts) = _events {
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
pub fn slice_to_hash(bytes: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];
	let bytes = &bytes[..array.len()]; // panics if not enough data
	array.copy_from_slice(bytes);
	array
}

pub fn get_wasm_hash(path: &str) -> Vec<String> {
	let sha_cmd = Command::new("sha256sum")
		.arg(path)
		.output()
		.unwrap_or_else(|_| panic!("Failed to get sha256sum of {}", path));

	std::str::from_utf8(&sha_cmd.stdout).unwrap()
		.split("  ")
		.map(|s| s.to_string())
		.collect()
}

pub fn call_trusted_stf<P: Pair>(api: &Api<P>, call: TrustedCall, rsa_pubkey: Rsa3072PubKey)
where
	MultiSignature: From<P::Signature>
{
	let call_encoded = call.encode();
	let mut call_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&call_encoded, &mut call_encrypted).unwrap();

	let xt = compose_extrinsic!(
        api.clone(),
        "SubstraTEERegistry",
        "call_worker",
		call_encrypted.clone()
    );

	// send and watch extrinsic until finalized
	let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
	info!("stf call extrinsic got finalized. Hash: {:?}", tx_hash);
	info!("waiting for confirmation of stf call");
	let act_hash = subscribe_to_call_confirmed(api.clone());
	info!("callConfirmed event received");
	debug!("Expected stf call Hash: {:?}", blake2s(32, &[0; 32], &call_encrypted).as_bytes());
	debug!("confirmation stf call Hash:   {:?}", act_hash);

}

pub fn get_trusted_stf_state(workerapi: &WorkerApi, getter: TrustedOperation) {
	let ret = workerapi.get_stf_state(getter);
	println!("    got getter response from worker: {:?}", ret);
	//TODO: decrypt response and verify signature
}
