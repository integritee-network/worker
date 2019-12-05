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

use log::*;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use std::str;
use substratee_stf;

use crate::enclave::api::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	pub account: String,
	pub amount: u32,
	pub sha256: sgx_sha256_hash_t
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
	let payload = substratee_stf::tests::get_test_balance_set_balance_call();
	let mut payload_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&payload, &mut payload_encrypted).unwrap();
	payload_encrypted
}

pub fn evaluate_result(result: sgx_status_t) {
	match result {
		sgx_status_t::SGX_SUCCESS => {
		},
		_ => {
			error!("[<] Error processing in enclave enclave");
			panic!("");
		}
	}
}
