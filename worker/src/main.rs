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
extern crate log;
extern crate wabt;

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
extern crate nan_preserving_float;

extern crate sgx_ucrypto as crypto;

mod utils;
mod constants;
mod enclave_api;
mod init_enclave;
mod ws_server;
mod enclave_wrappers;
mod wasm;
mod attestation_ocalls;

use log::*;
use std::fs;
use std::str;
use sgx_types::*;
use init_enclave::init_enclave;
use enclave_wrappers::*;
use ws_server::start_ws_server;

use substrate_api_client::{Api, hexstr_to_vec};
use my_node_runtime::{Event, Hash};

use parity_codec::Decode;
use std::sync::mpsc::channel;

use std::thread;

use wasm::{sgx_enclave_wasm_init};
use utils::check_files;

use enclave_api::get_ecc_signing_pubkey;
use constants::ATTN_REPORT_FILE;
use primitive_types::U256;
use parity_codec::Encode;
use my_node_runtime::{UncheckedExtrinsic};

use primitives::blake2_256;

extern {
	pub fn compose_extrinsic_register_enclave(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		attn_report : *const u8,
		attn_report_len: usize,
		genesis_hash: *const u8,
		genesis_hash_size: u32,
		nonce: *const u8,
		nonce_size: u32,
		unchecked_extrinsic: *mut u8,
		unchecked_extrinsic_size: u32
	) -> sgx_status_t;
}

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("port").unwrap_or("9944");
	info!("Interacting with port {}", port);

	if let Some(_matches) = matches.subcommand_matches("worker") {
		println!("*** Starting substraTEE-worker\n");
		worker(port);
	} else if matches.is_present("getpublickey") {
		println!("*** Get the public key from the TEE\n");
		get_public_key_tee();
	} else if matches.is_present("getsignkey") {
		println!("*** Get the signing key from the TEE\n");
		get_signing_key_tee();
	} else if matches.is_present("ra") {
		println!("*** Request a Remote Attestation\n");
		remote_attestation(port);
	} else {
		println!("For options: use --help");
	}
}

extern {
	fn perform_ra(
		eid: sgx_enclave_id_t,
		retval: *mut sgx_status_t,
		sign_type: sgx_quote_sign_type_t
	) -> sgx_status_t;
}

fn remote_attestation(port: &str) {
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
	// perform a remote attestation
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
	let result = unsafe {
		perform_ra(enclave.geteid(), &mut retval, sign_type)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("ECALL success!");
		},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	// ------------------------------------------------------------------------
	// register the enclave

	// get the attestation report
	let attn_report_json = fs::read_to_string(ATTN_REPORT_FILE).expect("Unable to open attestation report file");
	let attn_report_string: String = serde_json::from_str(&attn_report_json).unwrap();
	let attn_report_vec = attn_report_string.as_bytes().to_vec();

	println!("------------------------------------------");
	println!("attn_report_string  = {:?}", attn_report_string);
	println!("attn_report_vec     = {:?}", attn_report_vec);
	println!("attn_report_vec_len = {:?}", attn_report_vec.len());

	// initialize the API to talk to the substraTEE-node
	let mut api = Api::new(format!("ws://127.0.0.1:{}", port));
	api.init();

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

	// get enclave's account nonce
	let nonce = get_account_nonce(&api, pubkey);
	let nonce_bytes = U256::encode(&nonce);
	println!("nonce of TEE = {:?}", nonce);

	let mut retval = sgx_status_t::SGX_SUCCESS;

	let genesis_hash = api.genesis_hash.unwrap().as_bytes().to_vec();

	let unchecked_extrinsic_size = attn_report_vec.len() + 106;
	// let unchecked_extrinsic_size = 105; // for empty message
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let result = unsafe {
		compose_extrinsic_register_enclave(enclave.geteid(),
					 &mut retval,
					 attn_report_vec.as_ptr() as * const u8,
					 attn_report_vec.len(),
					 genesis_hash.as_ptr(),
					 genesis_hash.len() as u32,
					 nonce_bytes.as_ptr(),
					 nonce_bytes.len() as u32,
					 unchecked_extrinsic.as_mut_ptr(),
					 unchecked_extrinsic_size as u32
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => println!("[+] ECALL Enclave successful"),
		_ => {
			error!("[-] ECALL Enclave Failed {}!", result.as_str());
		}
	}

	// println!("unchecked_extrinsic = {:?}", unchecked_extrinsic);

	let ue = UncheckedExtrinsic::decode(&mut unchecked_extrinsic.as_slice()).unwrap();
	println!("-----------------------------------------------");
	println!("ue = {:?}", ue);

	let mut _xthex = hex::encode(ue.encode());
	_xthex.insert_str(0, "0x");
	println!("-----------------------------------------------");
	println!("_xthex = {:?}", _xthex);

	// sending the extrinsic
	let tx_hash = api.send_extrinsic(_xthex).unwrap();
	println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);

}

fn worker(port: &str) {
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

	// start the websocket server
	start_ws_server(enclave.geteid());

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

	let mut status = sgx_status_t::SGX_SUCCESS;

	// ------------------------------------------------------------------------
	// subscribe to events and react on firing
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
							}},
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
						}
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
