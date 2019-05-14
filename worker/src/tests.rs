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

use std::str;
use sgx_types::*;
use sgx_crypto_helper::rsa3072::{Rsa3072PubKey};
use enclave_api::*;
use init_enclave::init_enclave;
use enclave_wrappers::*;

use substrate_api_client::Api;

use parity_codec::Encode;

pub fn test_pipeline(eid: sgx_enclave_id_t, mut ciphertext: Vec<u8>, retval: &mut sgx_status_t, port: &str) {
	println!("");
	println!("*** Test Pipeline");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			println!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	let mut api = Api::new(format!("ws://127.0.0.1:{}",port));
	api.init();

	let ct = get_test_ciphertext(eid, retval);
	let xt = decryt_and_process_payload(eid, ct, retval, port);

	let mut _xthex = hex::encode(xt.encode());
	_xthex.insert_str(0, "0x");

	let tx_hash = api.send_extrinsic(_xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
	enclave.destroy();
//	assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
}

pub fn test_get_counter() {
	println!("***Test get_counter");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			println!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let account = "Alice";
	let mut value = 0u8;

	let result = unsafe {
		get_counter(enclave.geteid(),
					&mut retval,
					account.as_ptr(),
					account.len() as u32,
					&mut value)
	};


	println!("Countervalue for Alice: {}", value);
	enclave.destroy();
	assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
}

// debug function called from tests
pub fn get_test_ciphertext(eid: sgx_enclave_id_t, retval: &mut sgx_status_t) -> Vec<u8> {
	let pubkey_size = 8192;
	let mut pubkey = vec![0u8; pubkey_size as usize];

	let result = unsafe {
		get_rsa_encryption_pubkey(eid,
								  retval,
								  pubkey.as_mut_ptr(),
								  pubkey_size
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
//			return;
		}
	}
	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();

	let mut ciphertext : Vec<u8> = Vec::new();
	let plaintext = b"Alice,42".to_vec();
	rsa_pubkey.encrypt_buffer(&plaintext, &mut ciphertext).unwrap();
	println!("ciphertext = {:?}", ciphertext);
	return ciphertext;
}
