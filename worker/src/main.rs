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

use std::fs::{self, File};
use std::io::stdin;
use std::io::Write;
use std::path::Path;
use std::str;
use std::sync::mpsc::channel;
use std::thread;

use sgx_types::*;
use sgx_urts::SgxEnclave;

use base58::{FromBase58, ToBase58};
use clap::{load_yaml, App};
use codec::{Decode, Encode};
use keyring::AccountKeyring;
use log::*;
use my_node_runtime::{
    substratee_registry::{Request, ShardIdentifier},
    Event, Hash, UncheckedExtrinsic,
};
use primitive_types::U256;
use primitives::{
    crypto::{AccountId32, Ss58Codec},
    sr25519, Pair,
};
use substrate_api_client::{
    extrinsic::xt_primitives::GenericAddress,
    utils::{hexstr_to_u256, hexstr_to_vec},
    Api,
};

use runtime_primitives::{traits::Verify, AnySignature};
type AccountId = <AnySignature as Verify>::Signer;

use enclave::api::{
    enclave_dump_ra, enclave_execute_stf, enclave_init, enclave_perform_ra, enclave_shielding_key,
    enclave_signing_key,
};
use enclave::init::init_enclave;
use enclave::tls_ra::{run, run_enclave_client, run_enclave_server, Mode};
use substratee_node_calls::get_worker_amount;
use substratee_worker_api::Api as WorkerApi;
use utils::{check_files, get_first_worker_that_is_not_equal_to_self};
use ws_server::start_ws_server;

mod constants;
mod enclave;
mod ipfs;
mod tests;
mod utils;
mod ws_server;

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

    if let Some(_matches) = matches.subcommand_matches("run") {
        println!("*** Starting substraTEE-worker\n");
        let shard: ShardIdentifier = match _matches.value_of("shard") {
            Some(value) => {
                let shard_vec = value.from_base58().unwrap();
                let mut shard = [0u8; 32];
                shard.copy_from_slice(&shard_vec[..]);
                shard.into()
            }
            _ => get_mrenclave().into(),
        };
        worker(&n_url, w_ip, w_port, mu_ra_port, shard);
    } else if matches.is_present("shielding-key") {
        info!("*** Get the public key from the TEE\n");
        let enclave = enclave_init().unwrap();
        let pubkey = enclave_shielding_key(enclave).unwrap();
        let file = File::create(constants::SHIELDING_KEY_FILE).unwrap();
        match serde_json::to_writer(file, &pubkey) {
            Err(x) => {
                error!(
                    "[-] Failed to write '{}'. {}",
                    constants::SHIELDING_KEY_FILE,
                    x
                );
            }
            _ => {
                println!(
                    "[+] File '{}' written successfully",
                    constants::SHIELDING_KEY_FILE
                );
            }
        }
        return;
    } else if matches.is_present("signing-key") {
        info!("*** Get the signing key from the TEE\n");
        let enclave = enclave_init().unwrap();
        let pubkey = enclave_signing_key(enclave).unwrap();
        debug!("[+] Signing key raw: {:?}", pubkey);
        match fs::write(constants::SIGNING_KEY_FILE, pubkey) {
            Err(x) => {
                error!(
                    "[-] Failed to write '{}'. {}",
                    constants::SIGNING_KEY_FILE,
                    x
                );
            }
            _ => {
                println!(
                    "[+] File '{}' written successfully",
                    constants::SIGNING_KEY_FILE
                );
            }
        }
        return;
    } else if matches.is_present("dump-ra") {
        info!("*** Perform RA and dump cert to disk");
        let enclave = enclave_init().unwrap();
        enclave_dump_ra(enclave).unwrap();
        return;
    } else if matches.is_present("mrenclave") {
        println!("{}", get_mrenclave().encode().to_base58());
        return;
    }
    if let Some(_matches) = matches.subcommand_matches("init-shard") {
        match _matches.values_of("shard") {
            Some(values) => {
                for shard in values {
                    if shard.len() != 2 * 32 {
                        panic!("shard must be 256bit hex string")
                    }
                    if hex::decode(shard).is_err() {
                        panic!("shard must be hex encoded")
                    }
                    init_shard(shard);
                }
            }
            _ => {
                let shard = get_mrenclave().encode().to_base58();
                init_shard(&shard);
            }
        };
    } else if let Some(_matches) = matches.subcommand_matches("test") {
        if _matches.is_present("mu-ra-server") {
            println!("*** Running Enclave MU-RA TLS server\n");
            run(Mode::Server, mu_ra_port);
        } else if _matches.is_present("mu-ra-client") {
            println!("*** Running Enclave MU-RA TLS client\n");
            run(Mode::Client, mu_ra_port);
        } else {
            tests::run_enclave_tests(_matches, node_port);
        }
    } else {
        println!("For options: use --help");
    }
}

fn worker(node_url: &str, w_ip: &str, w_port: &str, mu_ra_port: &str, shard: ShardIdentifier) {
    // ------------------------------------------------------------------------
    // check for required files
    check_files();
    // ------------------------------------------------------------------------
    // initialize the enclave
    #[cfg(feature = "production")]
    println!("*** Starting enclave in production mode");
    #[cfg(not(feature = "production"))]
    println!("*** Starting enclave in development mode");

    let enclave = enclave_init().unwrap();

    // ------------------------------------------------------------------------
    // start the ws server to listen for worker requests
    let w_url = format!("{}:{}", w_ip, w_port);
    start_ws_server(enclave.clone(), w_url.clone(), mu_ra_port.to_string());

    // ------------------------------------------------------------------------
    let eid = enclave.geteid();
    let ra_url = format!("{}:{}", w_ip, mu_ra_port);
    thread::spawn(move || {
        run_enclave_server(
            eid,
            sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
            &ra_url,
        )
    });

    // ------------------------------------------------------------------------
    // start the substrate-api-client to communicate with the node
    let alice = AccountKeyring::Alice.pair();
    println!("   Alice's account = {}", alice.public().to_ss58check());
    // alice is validator
    let api = Api::new(format!("ws://{}", node_url)).set_signer(alice.clone());

    info!("encoding Alice's public 	= {:?}", alice.public().0.encode());
    let alice_acc = AccountId32::from(*alice.public().as_array_ref());
    info!("encoding Alice's AccountId = {:?}", alice_acc.encode());

    let result_str = api
        .get_storage("Balances", "FreeBalance", Some(alice_acc.encode()))
        .unwrap();
    let funds = hexstr_to_u256(result_str).unwrap();
    println!("    Alice's free balance = {:?}", funds);
    let result_str = api
        .get_storage("System", "AccountNonce", Some(alice_acc.encode()))
        .unwrap();
    let result = hexstr_to_u256(result_str).unwrap();
    println!("    Alice's Account Nonce is {}", result.low_u32());

    // ------------------------------------------------------------------------
    // get required fields for the extrinsic
    let genesis_hash = api.genesis_hash.as_bytes().to_vec();

    // get the public signing key of the TEE
    let mut signing_key_raw = [0u8; 32];
    signing_key_raw.copy_from_slice(&enclave_signing_key(enclave.clone()).unwrap()[..]);
    // Attention: this HAS to be sr25519, although its a ed25519 key!
    let tee_public = sr25519::Public::from_raw(signing_key_raw);
    info!(
        "[+] Got ed25519 account of TEE = {}",
        tee_public.to_ss58check()
    );
    let tee_account_id = AccountId32::from(*tee_public.as_array_ref());

    // check the enclave's account balance
    let result_str = api
        .get_storage("Balances", "FreeBalance", Some(tee_account_id.encode()))
        .unwrap();
    let funds = hexstr_to_u256(result_str).unwrap();
    info!("TEE's free balance = {:?}", funds);

    if funds < U256::from(10) {
        println!("[+] bootstrap funding Enclave form Alice's funds");
        let xt = api.balance_transfer(GenericAddress::from(tee_account_id.clone()), 1000000);
        let xt_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
        info!("[<] Extrinsic got finalized. Hash: {:?}\n", xt_hash);

        //verify funds have arrived
        let result_str = api
            .get_storage("Balances", "FreeBalance", Some(tee_account_id.encode()))
            .unwrap();
        let funds = hexstr_to_u256(result_str).unwrap();
        info!("TEE's NEW free balance = {:?}", funds);
    }

    // ------------------------------------------------------------------------
    // perform a remote attestation and get an unchecked extrinsic back

    // get enclaves's account nonce
    let result_str = api
        .get_storage("System", "AccountNonce", Some(tee_account_id.encode()))
        .unwrap();
    let nonce = hexstr_to_u256(result_str).unwrap().low_u32();
    info!("Enclave nonce = {:?}", nonce);
    let nonce_bytes = nonce.encode();

    let uxt = enclave_perform_ra(
        enclave.clone(),
        genesis_hash,
        nonce_bytes.encode(),
        w_url.encode(),
    )
    .unwrap();
    // hex encode the extrinsic
    let ue = UncheckedExtrinsic::decode(&mut uxt.as_slice()).unwrap();
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
        }
        1 => {
            info!("one worker registered, should be me");
            let shardenc = shard.encode().to_base58();
            let path = format!(
                "{}/{}/{}",
                constants::SHARDS_PATH,
                &shardenc,
                constants::ENCRYPTED_STATE_FILE
            );
            if !Path::new(&path).exists() {
                panic!("shard {} hasn't been initialized", shardenc);
            }
        }
        _ => {
            println!("*** There are already workers registered, fetching keys from first one...");
            let w1 = get_first_worker_that_is_not_equal_to_self(&api, tee_account_id).unwrap();
            let w1_url = String::from_utf8_lossy(&w1.url[..]).to_string();
            let w_api = WorkerApi::new(w1_url.clone());
            let ra_port = w_api.get_mu_ra_port().unwrap();
            info!("Got Port for MU-RA from other worker: {}", ra_port);

            info!("Performing MU-RA");
            let w1_url_port: Vec<&str> = w1_url.split(':').collect();
            run_enclave_client(
                enclave.geteid(),
                sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                &format!("{}:{}", w1_url_port[0], ra_port),
            );
            println!();
            println!("[+] MU-RA successfully performed.\n");
        }
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
        let _events = Vec::<system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
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
                                }
                                _ => {
                                    info!("Ignoring unsupported balances event");
                                }
                            }
                        }
                        Event::substratee_registry(re) => {
                            println!("[+] Received substratee_registry event");
                            debug!("{:?}", re);
                            match &re {
                                my_node_runtime::substratee_registry::RawEvent::AddedEnclave(
                                    sender,
                                    worker_url,
                                ) => {
                                    println!("[+] Received AddedEnclave event");
                                    println!("    Sender (Worker):  {:?}", sender);
                                    println!(
                                        "    Registered URL: {:?}",
                                        str::from_utf8(worker_url).unwrap()
                                    );
                                    println!();
                                }
                                my_node_runtime::substratee_registry::RawEvent::Forwarded(
                                    request,
                                ) => {
                                    println!("[+] Received Forwarded event");
                                    debug!("    Request: {:?}", request);
                                    println!();
                                    process_request(enclave.clone(), request.clone(), node_url);
                                }
                                my_node_runtime::substratee_registry::RawEvent::CallConfirmed(
                                    sender,
                                    payload,
                                ) => {
                                    println!("[+] Received CallConfirmed event");
                                    debug!("    From:    {:?}", sender);
                                    debug!("    Payload: {:?}", hex::encode(payload));
                                    println!();
                                }
                                _ => {
                                    info!("Ignoring unsupported substratee_registry event");
                                }
                            }
                        }
                        _ => {
                            debug!("event = {:?}", evr);
                            info!("Ignoring event\n");
                        }
                    }
                }
            }
            Err(_) => error!("Couldn't decode event record list"),
        }
    }
}

pub fn process_request(enclave: SgxEnclave, request: Request, node_url: &str) {
    // new api client (the other one is busy listening to events)
    // FIXME: this might not be very performant. maybe split into api_listener and api_sender
    let mut _api = Api::<sr25519::Pair>::new(format!("ws://{}", node_url));
    info!("*** Ask the signing key from the TEE");
    let mut signing_key_raw = [0u8; 32];
    signing_key_raw.copy_from_slice(&enclave_signing_key(enclave.clone()).unwrap()[..]);

    // Attention: this HAS to be sr25519, although its a ed25519 key!
    let tee_public = sr25519::Public::from_raw(signing_key_raw);
    info!(
        "[+] Got ed25519 account of TEE = {}",
        tee_public.to_ss58check()
    );
    let tee_accountid = AccountId::from(tee_public);

    let result_str = _api
        .get_storage("System", "AccountNonce", Some(tee_accountid.encode()))
        .unwrap();

    let genesis_hash = _api.genesis_hash.as_bytes().to_vec();

    let nonce = hexstr_to_u256(result_str).unwrap().low_u32();
    info!("Enclave nonce = {:?}", nonce);
    let uxt = enclave_execute_stf(
        enclave,
        request.cyphertext,
        request.shard.encode(),
        genesis_hash,
        nonce.encode(),
    )
    .unwrap();
    info!("[<] Message decoded and processed in the enclave");
    let ue = UncheckedExtrinsic::decode(&mut uxt.as_slice()).unwrap();
    let mut _xthex = hex::encode(ue.encode());
    _xthex.insert_str(0, "0x");
    info!("[>] Confirm processing (send the extrinsic)");
    let tx_hash = _api.send_extrinsic(_xthex).unwrap();
    println!(
        "[<] Request Extrinsic got finalized. tx hash: {:?}\n",
        tx_hash
    );
}

fn init_shard(shard: &str) {
    let path = format!("{}/{}", constants::SHARDS_PATH, shard);
    println!("initializing shard at {}", path);
    fs::create_dir_all(path.clone()).expect("could not create dir");

    let path = format!("{}/{}", path, constants::ENCRYPTED_STATE_FILE);
    if Path::new(&path).exists() {
        println!("shard state exists. Overwrite? [y/N]");
        let buffer = &mut String::new();
        stdin().read_line(buffer);
        match buffer.trim() {
            "y" | "Y" => (),
            _ => return,
        }
    }
    let mut file = fs::File::create(path).unwrap();
    file.write_all(b"");
}

fn get_mrenclave() -> [u8; 32] {
    // query our own MRENCLAVE
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let _ = unsafe {
        sgx_init_quote(
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };
    ti.mr_enclave.m
}
