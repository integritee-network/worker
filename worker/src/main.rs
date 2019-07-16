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
extern crate substratee_worker_api;
extern crate substrate_keyring;
extern crate system;
extern crate wabt;
extern crate ws;

extern crate cid;
extern crate futures;
extern crate hyper;
extern crate ipfs_api;
extern crate multihash;
extern crate sha2;

use clap::App;
use constants::*;
use enclave_api::{perform_ra};
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
use utils::{check_files, get_first_worker_that_is_not_equal_to_self};
use wasm::sgx_enclave_wasm_init;
use ws_server::start_ws_server;
use enclave_tls_ra::{Mode, run_enclave_server, run_enclave_client};
use substratee_node_calls::get_worker_amount;
use substratee_worker_api::Api as WorkerApi;

mod utils;
mod constants;
mod enclave_api;
mod init_enclave;
mod ws_server;
mod enclave_wrappers;
mod enclave_tls_ra;
mod wasm;
mod attestation_ocalls;
mod ipfs;
mod tests;

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("port").unwrap_or("9944");
	info!("Interacting with node on  port {}", port);

	let w_port = matches.value_of("w-port").unwrap_or("2000");
	info!("Worker listening on  port {}", w_port);

	let mu_ra_port = matches.value_of("mu-ra-port").unwrap_or("3443");
	info!("MU-RA server on port {}", mu_ra_port);

	if let Some(_matches) = matches.subcommand_matches("worker") {
		println!("*** Starting substraTEE-worker\n");
		worker(port, w_port, mu_ra_port);
	} else if matches.is_present("getpublickey") {
		println!("*** Get the public key from the TEE\n");
		get_public_key_tee();
	} else if matches.is_present("getsignkey") {
		println!("*** Get the signing key from the TEE\n");
		get_signing_key_tee();
	} else if matches.is_present("run_server") {
		println!("*** Running Enclave TLS server\n");
		enclave_tls_ra::run(Mode::Server, mu_ra_port);
	} else if matches.is_present("run_client") {
		println!("*** Running Enclave TLS client\n");
		enclave_tls_ra::run(Mode::Client, mu_ra_port);
	} else if let Some(m) = matches.subcommand_matches("test_enclave") {
		tests::run_enclave_tests(m, port);
	} else {
		println!("For options: use --help");
	}
}

fn worker(port: &str, w_port: &str, mu_ra_port: &str) {
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
	let w_url = format!("127.0.0.1:{}", w_port);
	start_ws_server(enclave.geteid(), w_url.clone(), mu_ra_port.to_string());

	// ------------------------------------------------------------------------
	let eid = enclave.geteid();
	let p = mu_ra_port.to_string().clone();
	thread::spawn(move || {
		run_enclave_server(eid, sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, &p)
	});

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

	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		println!("[-] Remote attestation of the enclave failed.\n");
		return;
	}

	println!();
	println!("[+] Remote attestation of the enclave successful\n");

	// hex encode the extrinsic
	let ue = UncheckedExtrinsic::decode(&mut unchecked_extrinsic.as_slice()).unwrap();
	let mut _xthex = hex::encode(ue.encode());
	_xthex.insert_str(0, "0x");

	// send the extrinsic and wait for confirmation
	println!("[>] Register the enclave (send the extrinsic)");
	let tx_hash = api.send_extrinsic(_xthex).unwrap();
	println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);


	match get_worker_amount(&api) {
		0 => {
			error!("No worker in registry after registering!");
			return;
		},
		1 => {
			info!("one worker registered, should be me");
		},
		_ => {
			println!("*** There are already workers registered, fetching keys from first one...");
			let w1 = get_first_worker_that_is_not_equal_to_self(&api, ecc_key).unwrap();

			let w_api = WorkerApi::new(w1.url.clone());
			let ra_port = w_api.get_mu_ra_port().unwrap();
			info!("Got Port for MU-RA from other worker: {}", ra_port);

			info!("Performing MU-RA");
			let w1_url_port: Vec<&str> = w1.url.split(':').collect();
			run_enclave_client(enclave.geteid(), sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, &format!("{}:{}", w1_url_port[0], ra_port));
			println!();
			println!("[+] MU-RA successfully performed.\n");
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
								my_node_runtime::substratee_registry::RawEvent::Forwarded(sender, payload) => {
									println!("[+] Received Forwarded event");
									debug!("    From:    {:?}", sender);
									debug!("    Payload: {:?}", hex::encode(payload));
									println!();

									// process the payload and send extrinsic
									process_forwarded_payload(enclave.geteid(), payload.to_vec(), &mut status, port);
								},
								my_node_runtime::substratee_registry::RawEvent::CallConfirmed(sender, payload) => {
									println!("[+] Received CallConfirmed event");
									debug!("    From:    {:?}", sender);
									debug!("    Payload: {:?}", hex::encode(payload));
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
