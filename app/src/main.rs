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
mod enclave_wrappers;
mod tests;

use std::str;
use std::fs;
use sgx_types::*;
use init_enclave::init_enclave;
use enclave_wrappers::*;
use ws_server::start_ws_server;
use tests::{test_pipeline, test_get_counter};

use substrate_api_client::{Api,  hexstr_to_vec};
use my_node_runtime::Event;

use parity_codec::Decode;
use std::sync::mpsc::channel;

use std::thread;

fn main() {
	// Setup logging
    env_logger::init();

    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

	let port = matches.value_of("port").unwrap_or("9944");
	println!("Intercating with port {}", port);

    if let Some(_matches) = matches.subcommand_matches("worker") {
		println!("* Starting substraTEE-worker");
		println!("");
		worker(port);
		println!("* Worker finished");
	} else if let Some(_matches) = matches.subcommand_matches("tests") {
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
