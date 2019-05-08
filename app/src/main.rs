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
extern crate primitives;
extern crate system;
extern crate rust_base58;
extern crate ws;
extern crate env_logger;

mod constants;
mod utils;
mod enclave_api;
mod init_enclave;
mod ws_server;

use std::str;
use std::fs;
use sgx_types::*;
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use constants::*;
use enclave_api::*;
use init_enclave::init_enclave;
use ws_server::start_ws_server;

use primitives::{
	 ed25519,
	sr25519,
	hexdisplay::HexDisplay,
	Pair,
	crypto::Ss58Codec,
	blake2_256,
};

use substrate_keyring::AccountKeyring;
use substrate_api_client::{Api, hexstr_to_u256, hexstr_to_vec};
use my_node_runtime::{UncheckedExtrinsic, SubstraTEEProxyCall, Event};
use parity_codec::{Decode, Encode, Codec, Input, HasCompact};
use primitive_types::U256;

use node_primitives::{
	Index,
	Hash,
	AccountId,
};
use rust_base58::{ToBase58};

// use ws::{connect, listen, CloseCode, Sender, Handler, Message, Result};
use std::thread::sleep;
use std::time::Duration;

use std::sync::mpsc::channel;
use std::thread;

fn main() {
	// Setup logging
    env_logger::init();

    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("port").unwrap_or("9944");
	println!("Intercating with port {}", port);

    if let Some(matches) = matches.subcommand_matches("worker") {
		println!("* Starting substraTEE-worker");
		println!("");
		worker(port);
		println!("* Worker finished");
	} else if let Some(matches) = matches.subcommand_matches("tests") {
//		test_pipeline(port);
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

	// start the websocket server
	start_ws_server(enclave.geteid());

	let mut status = sgx_status_t::SGX_SUCCESS;

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
		let event_str = events_out.recv().unwrap();

		let _unhex = hexstr_to_vec(event_str);
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<system::EventRecord::<Event>>::decode(&mut _er_enc);
		match _events {
			Some(evts) => {
				for evr in &evts {
					println!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
					match &evr.event {
						Event::balances(be) => {
							println!("\n>>>>>>>>>> balances event: {:?}\n", be);
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
							}},
						Event::substratee_proxy(pe) => {
							println!("\n>>>>>>>>>> substratee_Proxy event: {:?}", pe);
							match &pe {
								my_node_runtime::substratee_proxy::RawEvent::Forwarded(sender, payload) => {
									println!("received forward call from {:?} with payload {}", sender, hex::encode(payload));
									test_pipeline(enclave.geteid(), payload.to_vec(), &mut status, port);

								},
								my_node_runtime::substratee_proxy::RawEvent::CallConfirmed(sender, payload) => {
									println!("received confirm call from {:?} with payload {}", sender, hex::encode(payload));
								},
								_ => {
									println!("ignoring unsupported substratee_proxy event");
								},
							}
						}
						_ => {
							println!("ignoring unsupported module event: {:?}", evr)
						},
					}

				}
			}
			None => println!("couldn't decode event record list")
		}
	}
}

// only used for testing purposes
// FIXME: move to dedicated testing file
fn decryt_and_process_payload(eid: sgx_enclave_id_t, mut ciphertext: Vec<u8>, retval: &mut sgx_status_t, port: &str) -> UncheckedExtrinsic {
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
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	// Fixme: create string, and write to file
	println!("[+] ECC public key from TEE = {:?}", pubkey);
	match fs::write(ECC_PUB_KEY, pubkey) {
		Err(x) => { println!("[-] Failed to write '{}'. {}", ECC_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", ECC_PUB_KEY); }
	}

}


fn test_pipeline(eid: sgx_enclave_id_t, mut ciphertext: Vec<u8>, retval: &mut sgx_status_t, port: &str) {
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

