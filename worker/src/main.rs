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
use std::sync::mpsc::channel;
use std::thread;

use sgx_types::*;

use clap::{App, load_yaml};
use codec::{Decode, Encode};
use keyring::AccountKeyring;
use log::*;
use my_node_runtime::{Event, Hash, UncheckedExtrinsic};
use primitive_types::U256;
use primitives::{crypto::{AccountId32, Ss58Codec}, Pair, sr25519};
use substrate_api_client::{Api,
						   extrinsic::{xt_primitives::GenericAddress},
						   utils::{hexstr_to_u256, hexstr_to_vec}
};

use enclave::api::{get_ecc_signing_pubkey, init, perform_ra};
use enclave::tls_ra::{Mode, run, run_enclave_client, run_enclave_server};
use enclave::wrappers::{get_public_key_tee, get_signing_key_tee, process_request};
use enclave::init::init_enclave;
use substratee_node_calls::get_worker_amount;
use substratee_worker_api::Api as WorkerApi;
use utils::{check_files, get_first_worker_that_is_not_equal_to_self};
use ws_server::start_ws_server;

mod utils;
mod constants;
mod enclave;
mod ws_server;
mod ipfs;
mod tests;

fn main() {
	// Setup logging
	env_logger::init();

	let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let node_ip = matches.value_of("node-server").unwrap_or("127.0.0.1");
	let node_port = matches.value_of("node-port").unwrap_or("9944");
	let n_url = format!("{}:{}", node_ip, node_port);
	info!("Interacting with node on {}", n_url);

	let w_ip = matches.value_of("w-server").unwrap_or("127.0.0.1");
	let w_port = matches.value_of("w-port").unwrap_or("2000");
	info!("Worker listening on {}:{}", w_ip, w_port);

	let mu_ra_port = matches.value_of("mu-ra-port").unwrap_or("3443");
	info!("MU-RA server on port {}", mu_ra_port);

	if let Some(_matches) = matches.subcommand_matches("worker") {
		println!("*** Starting substraTEE-worker\n");
		worker(&n_url, w_ip, w_port, mu_ra_port);
	} else if matches.is_present("getpublickey") {
		println!("*** Get the public key from the TEE\n");
		get_public_key_tee();
	} else if matches.is_present("getsignkey") {
		println!("*** Get the signing key from the TEE\n");
		get_signing_key_tee();
	} else if matches.is_present("run_server") {
		println!("*** Running Enclave TLS server\n");
		run(Mode::Server, mu_ra_port);
	} else if matches.is_present("run_client") {
		println!("*** Running Enclave TLS client\n");
		run(Mode::Client, mu_ra_port);
	} else if let Some(m) = matches.subcommand_matches("test_enclave") {
		tests::run_enclave_tests(m, node_port);
	} else {
		println!("For options: use --help");
	}
}

fn worker(node_url: &str, w_ip: &str, w_port: &str, mu_ra_port: &str) {
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
	#[cfg(feature = "production")]
	println!("*** Starting enclave in production mode");
	#[cfg(not(feature = "production"))]
	println!("*** Starting enclave in development mode");


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

	println!("*** call enclave init()");
	let result = unsafe {
		init(
			enclave.geteid(),
			&mut status,
		)
	};

	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		println!("[-] init() failed.\n");
		return;
	}

	// ------------------------------------------------------------------------
	// start the ws server to listen for worker requests
	let w_url = format!("{}:{}", w_ip, w_port);
	start_ws_server(enclave.geteid(), w_url.clone(), mu_ra_port.to_string());

	// ------------------------------------------------------------------------
	let eid = enclave.geteid();
	let ra_url = format!("{}:{}", w_ip, mu_ra_port);
	thread::spawn(move || {
		run_enclave_server(eid, sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE, &ra_url)
	});

	// ------------------------------------------------------------------------
	// start the substrate-api-client to communicate with the node
	let alice = AccountKeyring::Alice.pair();
	println!("   Alice's account = {}", alice.public().to_ss58check());
	// alice is validator
	let api = Api::new(format!("ws://{}", node_url))
		.set_signer(alice.clone());

	info!("encoding Alice's public 	= {:?}", alice.public().0.encode());
	let alice_acc = AccountId32::from(*alice.public().as_array_ref());
	info!("encoding Alice's AccountId = {:?}", alice_acc.encode());

	let result_str = api.get_storage("Balances", "FreeBalance", Some(alice_acc.encode())).unwrap();
	let funds = hexstr_to_u256(result_str).unwrap();
	println!("    Alice's free balance = {:?}", funds);
	let result_str = api.get_storage("System", "AccountNonce", Some(alice_acc.encode())).unwrap();
	let result = hexstr_to_u256(result_str).unwrap();
	println!("    Alice's Account Nonce is {}", result.low_u32());


	// ------------------------------------------------------------------------
	// get required fields for the extrinsic
	let genesis_hash = api.genesis_hash.as_bytes().to_vec();

	// get the public signing key of the TEE
	println!("*** Ask the signing key from the TEE");
	let tee_pubkey_size = 32;
	let mut tee_pubkey = [0u8; 32];

	let mut status = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_ecc_signing_pubkey(enclave.geteid(),
							   &mut status,
							   tee_pubkey.as_mut_ptr(),
							   tee_pubkey_size
		)
	};
	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			error!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}
	// Attention: this HAS to be sr25519, although its a ed25519 key!
	let tee_public = sr25519::Public::from_raw(tee_pubkey);
	info!("[+] Got ed25519 account of TEE = {}", tee_public.to_ss58check());
	//info!("[+] Got ed25519 public raw of  TEE = {:?}", tee_pubkey);
	let tee_account_id = AccountId32::from(*tee_public.as_array_ref());

	// check the enclave's account balance
	let result_str = api.get_storage("Balances", "FreeBalance", Some(tee_account_id.encode())).unwrap();
	let funds = hexstr_to_u256(result_str).unwrap();
	info!("TEE's free balance = {:?}", funds);

	if funds < U256::from(10) {
		println!("[+] bootstrap funding Enclave form Alice's funds");
		let xt = api.balance_transfer(GenericAddress::from(tee_account_id.clone()), 1000000);
		let xt_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
		info!("[<] Extrinsic got finalized. Hash: {:?}\n", xt_hash);

		//verify funds have arrived
		let result_str = api.get_storage("Balances", "FreeBalance", Some(tee_account_id.encode())).unwrap();
		let funds = hexstr_to_u256(result_str).unwrap();
		info!("TEE's NEW free balance = {:?}", funds);
	}


	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back

	// get enclaves's account nonce
	let result_str = api.get_storage("System", "AccountNonce", Some(tee_account_id.encode())).unwrap();
	let nonce = hexstr_to_u256(result_str).unwrap().low_u32();
	info!("Enclave nonce = {:?}", nonce);
	let nonce_bytes = nonce.encode();

	// prepare the unchecked extrinsic
	// the size is determined in the enclave
	let unchecked_extrinsic_size = 5000;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

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
			let w1 = get_first_worker_that_is_not_equal_to_self(&api, tee_pubkey.to_vec()).unwrap();

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

		let _unhex = hexstr_to_vec(event_str).unwrap();
		let mut _er_enc = _unhex.as_slice();
		let _events = Vec::<system::EventRecord::<Event, Hash>>::decode(&mut _er_enc);
		match _events {
			Ok(evts) => {
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
								my_node_runtime::substratee_registry::RawEvent::Forwarded(sender, request) => {
									println!("[+] Received Forwarded event");
									debug!("    From:    {:?}", sender);
									debug!("    Request: {:?}", hex::encode(request));
									println!();
									process_request(enclave.geteid(), request.to_vec(), node_url);
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
			Err(_) => error!("Couldn't decode event record list")
		}
	}
}
