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
use clap::App;

extern crate sgx_types;
extern crate sgx_urts;
extern crate sgx_crypto_helper;

extern crate my_node_runtime;
extern crate substrate_api_client;
extern crate parity_codec;
extern crate substrate_keyring;
extern crate node_primitives;
extern crate primitive_types;

mod constants;
mod utils;
mod enclave_api;
mod init_enclave;

use std::str;
use std::fs;
use sgx_types::*;
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use constants::*;
use enclave_api::*;
use init_enclave::init_enclave;

use substrate_keyring::AccountKeyring;
use substrate_api_client::{Api, hexstr_to_u256, hexstr_to_vec};
use my_node_runtime::{UncheckedExtrinsic, SubstraTEEProxyCall};
use parity_codec::{Decode, Encode, Codec, Input, HasCompact};
use primitive_types::U256;

use node_primitives::{
	Index,
	Hash,
	AccountId,
};

use std::sync::mpsc::channel;
use std::thread;

fn main() {
    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    if let Some(matches) = matches.subcommand_matches("worker") {
		println!("* Starting substraTEE-worker");
		println!("");
		let port = matches.value_of("port").unwrap_or("9944");
		println!("Worker listening on port {}", port);
		worker(port);
		println!("* Worker finished");
	} else if matches.is_present("tests") {
		test_pipeline();
//		test_get_counter();
	} else if matches.is_present("getpublickey") {
		get_public_key_tee();
	} else if matches.is_present("getsignkey") {
		get_signing_key_tee();
	} else {
        println!("For options: use --help");
    }
}

fn worker(port: &str) -> () {
    // ------------------------------------------------------------------------
    // initialize the enclave
    println!("");
    println!("*** Starting enclave");
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
    // ------------------------------------------------------------------------
    // subscribe to events and react on firing
    println!("");
    println!("*** Subscribing to events");
	let mut api = Api::new(format!("ws://127.0.0.1:{}", port));
	api.init();

	let (events_in, events_out) = channel();

	let _eventsubscriber = thread::Builder::new()
		.name("eventsubscriber".to_owned())
		.spawn(move || {
			api.subscribe_events(events_in.clone());
		})
		.unwrap();

	loop {
		let event = events_out.recv().unwrap();
		match &event {
			my_node_runtime::Event::balances(be) => {
				println!(">>>>>>>>>> balances event: {:?}", be);
				match &be {
					balances::RawEvent::Transfer(transactor, dest, value, fee) => {
						println!("Transactor: {:?}", transactor);
						println!("Destination: {:?}", dest);
						println!("Value: {:?}", value);
						println!("Fee: {:?}", fee);
					},
					_ => {
						println!("ignoring unsupported balances event");
					},
				}
			},
			my_node_runtime::Event::substratee_proxy(pe) => {
				println!(">>>>>>>>>> substratee_Proxy event: {:?}", pe);
				match &pe {
					my_node_runtime::substratee_proxy::RawEvent::Forwarded(sender, payload) => {
						println!("received forward call from {:?} with payload {}", sender, hex::encode(payload));
					},
					_ => {
						println!("ignoring unsupported substratee_proxy event");
					},
				}
			}
			_ => {
				println!("ignoring unsupported module event: {:?}", event)
			},
		}
	}

    // ------------------------------------------------------------------------
    // compose an extrinsic with the hash of the initial payload
    // println!("");
    // println!("*** Compose extrinsic");
    // println!("**** TODO");

    // ------------------------------------------------------------------------
    // send the extrinsic
    // println!("");
    // println!("*** Send extrinsic");
    // println!("**** TODO");

    // ------------------------------------------------------------------------
    // destroy the enclave
    // println!("");
    // println!("*** Destroy enclave");
    // enclave.destroy();
}

fn decryt_and_process_payload(eid: sgx_enclave_id_t, mut ciphertext: Vec<u8>, retval: &mut sgx_status_t) -> UncheckedExtrinsic {
	// encoded message 'b"Alice, 42"'
	println!("");
	println!("*** Decrypt and process the payload");
	// ciphertext = [35, 238, 142, 104, 209, 142, 188, 217, 158, 7, 107, 10, 12, 166, 221, 243, 6, 226, 186, 246, 237, 96, 37, 245, 134, 4, 113, 61, 182, 177, 228, 98, 209, 76, 15, 232, 184, 172, 110, 221, 152, 186, 106, 248, 173, 140, 41, 17, 97, 169, 140, 150, 138, 94, 27, 243, 196, 30, 68, 56, 13, 206, 32, 0, 255, 144, 140, 79, 76, 55, 219, 246, 14, 222, 234, 28, 187, 235, 117, 158, 71, 26, 229, 192, 209, 129, 138, 162, 184, 201, 95, 5, 62, 171, 193, 156, 237, 112, 115, 4, 222, 101, 171, 166, 79, 91, 102, 137, 241, 144, 96, 232, 179, 216, 216, 152, 246, 243, 155, 120, 133, 117, 65, 145, 176, 138, 228, 253, 117, 121, 21, 217, 141, 189, 55, 242, 233, 148, 121, 181, 197, 79, 134, 97, 169, 195, 71, 112, 166, 175, 147, 128, 178, 212, 224, 12, 73, 159, 242, 31, 124, 106, 134, 122, 154, 16, 108, 39, 185, 32, 8, 106, 26, 0, 235, 142, 106, 232, 6, 45, 6, 221, 100, 17, 21, 78, 100, 204, 176, 193, 91, 185, 61, 51, 57, 143, 146, 60, 170, 58, 222, 1, 182, 74, 181, 159, 82, 23, 135, 62, 115, 44, 143, 237, 96, 248, 250, 197, 225, 41, 208, 103, 234, 135, 86, 115, 173, 115, 72, 34, 230, 205, 210, 236, 136, 241, 65, 136, 42, 53, 148, 240, 73, 220, 105, 114, 167, 109, 209, 37, 186, 177, 100, 242, 9, 46, 0, 161, 90, 110, 243, 32, 164, 61, 102, 17, 139, 219, 210, 16, 118, 110, 156, 153, 169, 43, 242, 209, 10, 174, 167, 30, 250, 137, 25, 53, 86, 202, 125, 180, 208, 178, 111, 132, 150, 197, 182, 156, 248, 177, 225, 45, 187, 13, 235, 2, 126, 190, 136, 36, 140, 229, 22, 7, 181, 207, 115, 126, 205, 229, 168, 251, 105, 201, 134, 201, 197, 166, 166, 200, 60, 188, 86, 180, 175, 186, 238, 117, 210, 8, 202, 44, 233, 190, 17, 17, 209, 179, 185, 0, 169, 42, 191, 174, 78, 153, 128, 212, 237, 39, 87, 182, 251, 10, 100, 12, 79, 70, 242, 154, 243, 83, 123, 183, 131, 237, 197, 175, 116, 108, 45, 213, 172, 26].to_vec();

	// Fixme: handle variable enclave output: https://stackoverflow.com/questions/49395654/pass-variable-size-buffer-from-sgx-enclave-to-outside
	let extrinsic_size = 112;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; extrinsic_size as usize];

	let mut api = Api::new(format!("ws://127.0.0.1:9991"));
	api.init();
	let genesis_hash = api.genesis_hash.unwrap().as_bytes().to_vec();

	// get Alice's AccountNonce
	let accountid = AccountId::from(AccountKeyring::Alice);
	let nonce_str = api.get_storage("System", "AccountNonce", Some(accountid.encode())).unwrap();
	println!("");
	println!("[+] Alice's account nonce is {}", nonce_str);
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
	Decode::decode(&mut unchecked_extrinsic.as_slice()).unwrap()
}

fn get_public_key_tee()
{
	println!("");
	println!("*** Get the public key from the TEE");

	println!("");
	println!("*** Starting enclave");
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

	// define the size
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
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();

	println!("[+] RSA3072 public key from TEE = {:?}", rsa_pubkey);

	let rsa_pubkey_json = serde_json::to_string(&rsa_pubkey).unwrap();
	match fs::write(RSA_PUB_KEY, rsa_pubkey_json) {
		Err(x) => { println!("[-] Failed to write '{}'. {}", RSA_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", RSA_PUB_KEY); }
	}
}

fn get_signing_key_tee() {
	println!("");
	println!("*** Get the signing key from the TEE");

	println!("");
	println!("*** Starting enclave");
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

	// define the size
	let pubkey_size = 32;
	let mut pubkey = vec![0u8; pubkey_size as usize];

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
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	// Fixme: create string, and write to file
	println!("[+] ECC public key from TEE = {:?}", &pubkey);

}


fn test_pipeline() {
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
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let mut ct = get_test_ciphertext(enclave.geteid(), &mut retval);
	let xt = decryt_and_process_payload(enclave.geteid(), ct, &mut retval);

	// send and watch extrinsic until finalized
	let mut api = Api::new("ws://127.0.0.1:9991".to_string());
	api.init();
	let tx_hash = api.send_extrinsic(xt).unwrap();

	println!("[+] Transaction got finalized. Hash: {:?}", tx_hash);
	println!("");

	enclave.destroy();
	assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
}

fn test_get_counter() {
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
	let account = b"Alice";
	let mut value = 0u8;

	let result = unsafe {
		get_counter(enclave.geteid(),
					&mut retval,
					account.to_vec().as_ptr(),
					account.len() as u32,
					&mut value)
	};


	println!("Countervalue for Alice: {}", value);
	enclave.destroy();
	assert_eq!(retval, sgx_status_t::SGX_SUCCESS);
}

// debug function called from tests
fn get_test_ciphertext(eid: sgx_enclave_id_t, retval: &mut sgx_status_t) -> Vec<u8> {
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

