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

use enclave_api::*;
//use enclave_wrappers::get_account_nonce;
use log::*;
//use parity_codec::{Compact, Encode};
//use primitive_types::U256;
use primitives::{ed25519, Pair};
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use std::str;
use substrate_api_client::Api;
use utils;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	pub account: String,
	pub amount: u32,
	pub sha256: sgx_sha256_hash_t
}

pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];
	let bytes = &bytes[..array.len()]; // panics if not enough data
	array.copy_from_slice(bytes);
	array
}

pub fn get_encrypted_msg(eid: sgx_enclave_id_t) -> Vec<u8> {
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

	evaluate_result(retval);
	evaluate_result(result);

	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();
	encrypt_msg(rsa_pubkey)
}

pub fn encrypt_msg(rsa_pubkey: Rsa3072PubKey) -> Vec<u8> {
	let hash: Vec<String> = utils::get_wasm_hash();
	println!("Wasm Hash: {:?}", hash[0]);
	println!("Wasm Binary : {:?}", hash[1]);

	let sha = hex::decode(hash[0].clone()).unwrap();
	let sha256: sgx_sha256_hash_t = from_slice(&sha);

	let account: String = "Alice".to_string();
	let amount = 42;

	let message = Message { account, amount, sha256 };
	let plaintext = serde_json::to_vec(&message).unwrap();
	let mut payload_encrypted: Vec<u8> = Vec::new();

	rsa_pubkey.encrypt_buffer(&plaintext, &mut payload_encrypted).unwrap();
	payload_encrypted
}

pub fn register_enclave() {
	let mut api = Api::new(format!("ws://127.0.0.1:{}", "9991"));
	api.init();

	let tee_ecc_seed = [244, 96, 170, 60, 77, 239, 28, 64, 51, 180, 208, 145, 76, 154, 198, 174,
		236, 162, 18, 135, 190, 84, 216, 155, 142, 175, 237, 238, 60, 219, 134, 184];
	let _pair = ed25519::Pair::from_seed(tee_ecc_seed);

//	let tx_hash = api.send_extrinsic(xthex).unwrap();
}

pub fn evaluate_result(result: sgx_status_t) {
	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("[<] Message decoded and processed in the enclave");
		},
		_ => {
			error!("[<] Error processing message in the enclave");
			panic!("");
		}
	}
}
