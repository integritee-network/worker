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
extern crate env_logger;
extern crate log;
extern crate my_node_runtime;
extern crate nan_preserving_float;
extern crate node_primitives;
extern crate parity_codec;
extern crate primitive_types;
extern crate primitives;
extern crate rust_base58;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_types;
extern crate sgx_ucrypto as crypto;
extern crate sgx_urts;
extern crate substrate_api_client;
extern crate substratee_node_calls;
extern crate substrate_keyring;
extern crate system;
extern crate wabt;
extern crate ws;

use clap::App;
use constants::*;
use enclave_api::{perform_ra, test_main_entrance};
use enclave_wrappers::*;
use init_enclave::init_enclave;
use log::*;
use my_node_runtime::{Event, Hash};
use my_node_runtime::UncheckedExtrinsic;
use parity_codec::Decode;
use parity_codec::Encode;
use primitive_types::U256;
use sgx_types::*;
use std::fs;
use std::str;
use std::sync::mpsc::channel;
use std::thread;
use substrate_api_client::{Api, hexstr_to_vec};
use utils::check_files;
use wasm::sgx_enclave_wasm_init;
use ws_server::start_ws_server;
use enclave_tls_ra::Mode;
use substratee_node_calls::get_worker_amount;

mod utils;
mod constants;
mod enclave_api;
mod init_enclave;
mod ws_server;
mod enclave_wrappers;
mod enclave_tls_ra;
mod wasm;
mod attestation_ocalls;

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("port").unwrap_or("9944");
	info!("Interacting with node on  port {}", port);

	let w_port = matches.value_of("port").unwrap_or("2000");
	info!("Worker listening on  port {}", w_port);

	if let Some(_matches) = matches.subcommand_matches("worker") {
		println!("*** Starting substraTEE-worker\n");
		worker(port, w_port);
	} else if matches.is_present("getpublickey") {
		println!("*** Get the public key from the TEE\n");
		get_public_key_tee();
	} else if matches.is_present("getsignkey") {
		println!("*** Get the signing key from the TEE\n");
		get_signing_key_tee();
	} else if matches.is_present("run_server") {
		println!("*** Running Enclave TLS server\n");
		enclave_tls_ra::run(Mode::Server);
	} else if matches.is_present("run_client") {
		println!("*** Running Enclave TLS client\n");
		enclave_tls_ra::run(Mode::Client);
	} else if matches.is_present("test_enclave") {
		println!("*** Running Enclave unit tests\n");
		run_enclave_unit_tests();
	} else {
		println!("For options: use --help");
	}
}

fn worker(port: &str, w_port: &str) {
	let mut status = sgx_status_t::SGX_SUCCESS;

	// ------------------------------------------------------------------------
	// check for required files
	let missing_files = check_files();
	match missing_files {
		0  => {
			debug!("All files found\n");
		},
		1 => {
			error!("Stopping as 1 required file is missing\n");
			return;
		},
		_ => {
			error!("Stopping as {} required files are missing\n", missing_files);
			return;
		}
	};

	// ------------------------------------------------------------------------
	// initialize the enclave
	println!("*** Starting enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!\n", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!\n", x);
			return;
		},
	};


	// ------------------------------------------------------------------------
	// initialize the sgxwasm specific driver engine
	let result = sgx_enclave_wasm_init(enclave.geteid());
	match result {
		Ok(_r) => {
			println!("[+] Init Wasm in enclave successful\n");
		},
		Err(x) => {
			error!("[-] Init Wasm in enclave failed {}!\n", x.as_str());
			return;
		},
	}

	// ------------------------------------------------------------------------
	// start the ws server to listen for worker requests
	let w_url = format!("ws://127.0.0.1:{}", w_port);
	start_ws_server(enclave.geteid(), w_url.clone());

	// ------------------------------------------------------------------------
	// start the substrate-api-client to communicate with the node
	let mut api = Api::new(format!("ws://127.0.0.1:{}", port));
	api.init();

	// ------------------------------------------------------------------------
	// get required fields for the extrinsic
	let genesis_hash = api.genesis_hash.unwrap().as_bytes().to_vec();

	// get the public signing key of the TEE
	let mut key = [0; 32];
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ECC public key file");
	key.copy_from_slice(&ecc_key[..]);
	info!("[+] Got ECC public key of TEE = {:?}", key);

	// get enclaves's account nonce
	let nonce = get_account_nonce(&api, key);
	let nonce_bytes = U256::encode(&nonce);
	info!("Enclave nonce = {:?}", nonce);

	// prepare the unchecked extrinsic
	// the size is determined in the enclave
	let unchecked_extrinsic_size = 5000;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back
	println!("*** Perform a remote attestation of the enclave");
	let result = unsafe {
		perform_ra(
			enclave.geteid(),
			&mut status,
			genesis_hash.as_ptr(),
			genesis_hash.len() as u32,
			nonce_bytes.as_ptr(),
			nonce_bytes.len() as u32,
			w_url.as_ptr(),
			w_url.len() as u32,
			unchecked_extrinsic.as_mut_ptr(),
			unchecked_extrinsic_size as u32
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("[+] Perform a remote attestation of the enclave successful\n");

			// hex encode the extrinsic
			let ue = UncheckedExtrinsic::decode(&mut unchecked_extrinsic.as_slice()).unwrap();
			let mut _xthex = hex::encode(ue.encode());
			_xthex.insert_str(0, "0x");

			// send the extrinsic and wait for confirmation
			println!("[>] Register the enclave (send the extrinsic)");
			let tx_hash = api.send_extrinsic(_xthex).unwrap();
			println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);
		},
		_ => {
			println!("[-] ECALL 'perform_ra' failed {}!", result.as_str());
			return;
		}
	}

	match get_worker_amount(&api) {
		0 => {
			error!("No worker in registry!");
			return;
		},
		1 => {
			info!("one worker registered.");
		},
		_ => {
			info!("There are already workers registered, fetching keys from first one.");
			enclave_tls_ra::run(Mode::Client);
			return;
		},
	};

	// ------------------------------------------------------------------------
	// subscribe to events and react on firing
	println!("*** Subscribing to events");
	let (events_in, events_out) = channel();

	let _eventsubscriber = thread::Builder::new()
		.name("eventsubscriber".to_owned())
		.spawn(move || {
			api.subscribe_events(events_in.clone());
		})
		.unwrap();

	println!("[+] Subscribed, waiting for event...");
	println!();
	loop {
		let event_str = events_out.recv().unwrap();

		let _unhex = hexstr_to_vec(event_str);
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<system::EventRecord::<Event, Hash>>::decode(&mut _er_enc);
		match _events {
			Some(evts) => {
				for evr in &evts {
					debug!("Decoded: phase = {:?}, event = {:?}", evr.phase, evr.event);
					match &evr.event {
						Event::balances(be) => {
							println!("[+] Received balances event");
							debug!("{:?}", be);
							match &be {
								balances::RawEvent::Transfer(transactor, dest, value, fee) => {
									println!("    Transactor:  {:?}", transactor);
									println!("    Destination: {:?}", dest);
									println!("    Value:       {:?}", value);
									println!("    Fee:         {:?}", fee);
									println!();
								},
								_ => {
									info!("Ignoring unsupported balances event");
								},
							}
						},
						Event::substratee_proxy(pe) => {
							println!("[+] Received substratee_proxy event");
							debug!("{:?}", pe);
							match &pe {
								my_node_runtime::substratee_proxy::RawEvent::Forwarded(sender, payload) => {
									println!("[+] Received Forwarded event");
									debug!("    From:    {:?}", sender);
									debug!("    Payload: {:?}", hex::encode(payload));
									println!();

									// process the payload and send extrinsic
									process_forwarded_payload(enclave.geteid(), payload.to_vec(), &mut status, port);
								},
								my_node_runtime::substratee_proxy::RawEvent::CallConfirmed(sender, payload) => {
									println!("[+] Received CallConfirmed event");
									debug!("    From:    {:?}", sender);
									debug!("    Payload: {:?}", hex::encode(payload));
									println!();
								},
							}
						},
						Event::substratee_registry(re) => {
							println!("[+] Received substratee_registry event");
							debug!("{:?}", re);
							match &re {
								my_node_runtime::substratee_registry::RawEvent::AddedEnclave(sender, worker_url) => {
									println!("[+] Received AddedEnclave event");
									println!("    Sender (Worker):  {:?}", sender);
									println!("    Registered URL: {:?}", str::from_utf8(worker_url).unwrap());
									println!();
								},
								_ => {
									info!("Ignoring unsupported substratee_registry event");
								},
							}
						},
						_ => {
							debug!("event = {:?}", evr);
							info!("Ignoring event\n");
						},
					}
				}
			}
			None => error!("Couldn't decode event record list")
		}
	}
}

fn run_enclave_unit_tests() {
	// ------------------------------------------------------------------------
	// initialize the enclave
	println!("*** Starting enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!\n", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!\n", x);
			return;
		},
	};

	let mut retval = 0usize;

	let result = unsafe {
		test_main_entrance(enclave.geteid(),
						   &mut retval)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	assert_eq!(retval, 0);
	println!("[+] unit_test ended!");

	enclave.destroy();
}
