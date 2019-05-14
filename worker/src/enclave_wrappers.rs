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
use std::fs;
use log::*;
use sgx_types::*;
use sgx_crypto_helper::rsa3072::{Rsa3072PubKey};
use constants::*;
use enclave_api::*;
use init_enclave::init_enclave;

use primitives::{ed25519};

use substrate_api_client::{Api, hexstr_to_u256};
use my_node_runtime::{UncheckedExtrinsic};
use parity_codec::{Decode, Encode};
use primitive_types::U256;

// only used for testing purposes
// FIXME: move to dedicated testing file
pub fn decryt_and_process_payload(eid: sgx_enclave_id_t, mut ciphertext: Vec<u8>, retval: &mut sgx_status_t, port: &str) -> UncheckedExtrinsic {
	// encoded message 'b"Alice, 42"'
	println!("");
	println!("*** Decrypt and process the payload");
	let extrinsic_size = 137;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; extrinsic_size as usize];

	let mut api = Api::new(format!("ws://127.0.0.1:{}", port));
	api.init();
	let genesis_hash = api.genesis_hash.unwrap().as_bytes().to_vec();

	let mut key = [0; 32];
	// get the public signing key of the TEE
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ecc pubkey file");
	key.copy_from_slice(&ecc_key[..]);
	println!("\n\n[+] Got ECC public key of TEE = {:?}\n\n", key);

	// get enclaves's AccountNonce
	let accountid = ed25519::Public::from_raw(key);
	println!("Enclaves account id: {:?}", accountid);

	let nonce_str = api.get_storage("System", "AccountNonce", Some(accountid.encode())).unwrap();
	println!("");
	println!("[+] Tee's account nonce is {}", nonce_str);
	let nonce_u = hexstr_to_u256(nonce_str);
	let nonce_bytes = U256::encode(&nonce_u);

	let result = unsafe {
		call_counter(eid,
					 retval,
					 ciphertext.as_mut_ptr(),
					 ciphertext.len() as u32,
					 genesis_hash.as_ptr(),
					 genesis_hash.len() as u32,
					 nonce_bytes.as_ptr(),
					 nonce_bytes.len() as u32,
					 unchecked_extrinsic.as_mut_ptr(),
					 extrinsic_size as u32
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => println!("[+] Message decoded and processed in the enclave."),
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
//			return;
		}
	}
	UncheckedExtrinsic::decode(&mut unchecked_extrinsic.as_slice()).unwrap()
}

pub fn get_signing_key_tee() {
	println!("");
	println!("*** Get the signing key from the TEE");

	println!("");
	println!("*** Start the enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	// request the key
	println!("");
	println!("*** Ask the signing key from the TEE");
	let pubkey_size = 32;
	let mut pubkey = [0u8; 32];

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_ecc_signing_pubkey(enclave.geteid(),
							   &mut retval,
							   pubkey.as_mut_ptr(),
							   pubkey_size
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			error!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	println!("[+] Signing key: {:?}", pubkey);

	println!("");
	println!("*** Write the ECC signing key to a file");
	match fs::write(ECC_PUB_KEY, pubkey) {
		Err(x) => { error!("[-] Failed to write '{}'. {}", ECC_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", ECC_PUB_KEY); }
	}

}

pub fn get_public_key_tee()
{
	println!("");
	println!("*** Get the public key from the TEE");

	println!("");
	println!("*** Start the enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	// request the key
	println!("");
	println!("*** Ask the public key from the TEE");
	let pubkey_size = 8192;
	let mut pubkey = vec![0u8; pubkey_size as usize];

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_rsa_encryption_pubkey(enclave.geteid(),
								  &mut retval,
								  pubkey.as_mut_ptr(),
								  pubkey_size
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			error!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();
	println!("[+] {:?}", rsa_pubkey);

	println!("");
	println!("*** Write the RSA3072 public key to a file");

	let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
	match fs::write(RSA_PUB_KEY, rsa_pubkey_json) {
		Err(x) => { error!("[-] Failed to write '{}'. {}", RSA_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", RSA_PUB_KEY); }
	}
}
