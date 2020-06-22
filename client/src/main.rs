//  Copyright (c) 2019 Alain Brenzikofer
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

//! an RPC client to substraTEE using websockets
//!
//! examples
//! substratee_client 127.0.0.1:9944 transfer //Alice 5G9RtsTbiYJYQYMHbWfyPoeuuxNaCbC16tZ2JGrZ4gRKwz14 1000
//!
#![feature(rustc_private)]
#[macro_use]
extern crate clap;
extern crate env_logger;
extern crate log;

extern crate chrono;
use chrono::{DateTime, Utc};
use std::time::{Duration, UNIX_EPOCH};

use sc_keystore::Store;
use sp_application_crypto::{ed25519, sr25519};
use sp_keyring::AccountKeyring;
use std::path::PathBuf;

use base58::{FromBase58, ToBase58};

use clap::{Arg, ArgMatches};
use clap_nested::{Command, Commander};
use codec::{Decode, Encode};
use log::*;
use sp_core::{crypto::Ss58Codec, hashing::blake2_256, sr25519 as sr25519_core, Pair, H256};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};

use std::sync::mpsc::channel;
use std::thread;

use std::convert::TryFrom;
use substrate_api_client::{
    compose_extrinsic, events::EventsDecoder, extrinsic::xt_primitives::UncheckedExtrinsicV4,
    node_metadata::Metadata, utils::hexstr_to_vec, Api, XtStatus,
};
use substratee_node_runtime::{
    substratee_registry::{Enclave, Request},
    AccountId, Event, Hash, Signature,
};
use substratee_stf::{
    cli::get_identifiers, ShardIdentifier, TrustedCallSigned, TrustedGetterSigned,
    TrustedOperationSigned,
};
use substratee_worker_api::Api as WorkerApi;

type AccountPublic = <Signature as Verify>::Signer;
const KEYSTORE_PATH: &str = "my_keystore";
const PREFUNDING_AMOUNT: u128 = 1_000_000_000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    env_logger::init();

    let res = Commander::new()
        .options(|app| {
            app.arg(
                Arg::with_name("node-url")
                    .short("u")
                    .long("node-url")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("ws://127.0.0.1")
                    .help("node url"),
            )
            .arg(
                Arg::with_name("node-port")
                    .short("p")
                    .long("node-port")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("9944")
                    .help("node port"),
            )
            .arg(
                Arg::with_name("worker-url")
                    .short("U")
                    .long("worker-url")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("ws://127.0.0.1")
                    .help("worker url"),
            )
            .arg(
                Arg::with_name("worker-port")
                    .short("P")
                    .long("worker-port")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("2000")
                    .help("worker port"),
            )
            .name("substratee-client")
            .version(VERSION)
            .author("Supercomputing Systems AG <info@scs.ch>")
            .about("interact with substraTEE node and workers")
            .after_help("stf subcommands depend on the stf crate this has been built against")
        })
        .args(|_args, matches| matches.value_of("environment").unwrap_or("dev"))
        .add_cmd(
            Command::new("new-account")
                .description("generates a new account for the substraTEE chain")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    let key: sr25519::AppPair = store.write().generate().unwrap();
                    drop(store);
                    println!("{}", key.public().to_ss58check());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-accounts")
                .description("lists all accounts in keystore for the substraTEE chain")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    println!("sr25519 keys:");
                    for pubkey in store
                        .read()
                        .public_keys::<sr25519::AppPublic>()
                        .unwrap()
                        .into_iter()
                    {
                        println!("{}", pubkey.to_ss58check());
                    }
                    println!("ed25519 keys:");
                    for pubkey in store
                        .read()
                        .public_keys::<ed25519::AppPublic>()
                        .unwrap()
                        .into_iter()
                    {
                        println!("{}", pubkey.to_ss58check());
                    }
                    drop(store);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("print-metadata")
                .description("query node metadata and print it as json to stdout")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let meta = get_chain_api(matches).get_metadata();
                    println!("Metadata:\n {}", Metadata::pretty_format(&meta).unwrap());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("faucet")
                .description("send some bootstrapping funds to an account")
                .options(|app| {
                    app.arg(
                        Arg::with_name("AccountId")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId to be funded"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let account = matches.value_of("AccountId").unwrap();
                    let accountid = get_accountid_from_str(account);
                    let _api = api.set_signer(AccountKeyring::Alice.pair());
                    let xt = _api.balance_transfer(accountid.clone(), PREFUNDING_AMOUNT);
                    info!(
                        "[+] Alice is generous and pre funds account {}\n",
                        accountid.to_ss58check()
                    );
                    let tx_hash = _api
                        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
                        .unwrap();
                    info!(
                        "[+] Pre-Funding transaction got finalized. Hash: {:?}\n",
                        tx_hash
                    );
                    let result = _api.get_account_data(&accountid).unwrap();
                    println!(
                        "balance for {} is now {}",
                        accountid.to_ss58check(),
                        result.free
                    );
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("balance")
                .description("query on-chain balance for AccountId")
                .options(|app| {
                    app.arg(
                        Arg::with_name("AccountId")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let account = matches.value_of("AccountId").unwrap();
                    let accountid = get_accountid_from_str(account);
                    let balance = if let Some(data) = api.get_account_data(&accountid) {
                        data.free
                    } else {
                        0
                    };
                    println!("balance for {} is {}", account, balance);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("transfer")
                .description("transfer funds from one on-chain account to another")
                .options(|app| {
                    app.arg(
                        Arg::with_name("from")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("sender's AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("recipient's AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("amount")
                            .takes_value(true)
                            .required(true)
                            .value_name("U128")
                            .help("amount to be transferred"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let arg_from = matches.value_of("from").unwrap();
                    let arg_to = matches.value_of("to").unwrap();
                    let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                        .expect("amount can be converted to u128");
                    let from = get_pair_from_str(arg_from);
                    let to = get_accountid_from_str(arg_to);
                    info!("from ss58 is {}", from.public().to_ss58check());
                    info!("to ss58 is {}", to.to_ss58check());
                    let _api = api.set_signer(sr25519_core::Pair::from(from));
                    let xt = _api.balance_transfer(to.clone(), amount);
                    let tx_hash = _api
                        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
                        .unwrap();
                    println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
                    let result = _api.get_account_data(&to).unwrap();
                    println!("balance for {} is now {}", to, result.free);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-workers")
                .description("query enclave registry and list all workers")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let wcount = get_enclave_count(&api);
                    println!("number of workers registered: {}", wcount);
                    for w in 1..=wcount {
                        let enclave = get_enclave(&api, w);
                        if enclave.is_none() {
                            println!("error reading enclave data");
                            continue;
                        };
                        let enclave = enclave.unwrap();
                        let timestamp = DateTime::<Utc>::from(
                            UNIX_EPOCH + Duration::from_millis(enclave.timestamp as u64),
                        );
                        println!("Enclave {}", w);
                        println!("   AccountId: {}", enclave.pubkey.to_ss58check());
                        println!("   MRENCLAVE: {}", enclave.mr_enclave.to_base58());
                        println!("   RA timestamp: {}", timestamp);
                        println!("   URL: {}", String::from_utf8(enclave.url).unwrap());
                    }
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("listen")
                .description("listen to on-chain events")
                .options(|app| {
                    app.arg(
                        Arg::with_name("events")
                            .short("e")
                            .long("exit-after")
                            .takes_value(true)
                            .help("exit after given number of SubstraTEE events"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    listen(matches);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("shield-funds")
                .description("Transfer funds from an on-chain account to an incognito account")
                .options(|app| {
                    app.arg(
                        Arg::with_name("from")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("Sender's on-chain AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("Recipient's incognito AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("amount")
                            .takes_value(true)
                            .required(true)
                            .value_name("U128")
                            .help("Amount to be transferred"),
                    )
                    .arg(
                        Arg::with_name("shard")
                            .takes_value(true)
                            .required(true)
                            .value_name("STRING")
                            .help("Shard identifier"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let chain_api = get_chain_api(matches);
                    let worker_api = get_worker_api(matches);
                    let shielding_pubkey = worker_api.get_rsa_pubkey().unwrap();

                    let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                        .expect("amount can't be converted to u128");

                    let shard_opt = match matches.value_of("shard") {
                        Some(s) => match s.from_base58() {
                            Ok(s) => ShardIdentifier::decode(&mut &s[..]),
                            _ => panic!("shard argument must be base58 encoded"),
                        },
                        _ => panic!("at least one of `mrenclave` or `shard` arguments must be supplied")
                    };
                    let shard = match shard_opt {
                        Ok(shard) => shard,
                        Err(e) => panic!(e),
                    };

                    // get the sender
                    let arg_from = matches.value_of("from").unwrap();
                    let from = get_pair_from_str(arg_from);
                    let chain_api = chain_api.set_signer(sr25519_core::Pair::from(from));

                    // get the recipient
                    let arg_to = matches.value_of("to").unwrap();
                    let to = get_accountid_from_str(arg_to);
                    let to_encoded = to.encode();
                    let mut to_encrypted: Vec<u8> = Vec::new();
                    shielding_pubkey
                        .encrypt_buffer(&to_encoded, &mut to_encrypted)
                        .unwrap();

                    // compose the extrinsic
                    let xt: UncheckedExtrinsicV4<([u8; 2], Vec<u8>, u128, H256)> = compose_extrinsic!(
                        chain_api,
                        "SubstrateeRegistry",
                        "shield_funds",
                        to_encrypted,
                        amount,
                        shard
                    );

                    let tx_hash = chain_api
                        .send_extrinsic(xt.hex_encode(), XtStatus::Finalized)
                        .unwrap();
                    println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
                    Ok(())
                }),
        )
        .add_cmd(substratee_stf::cli::cmd(&perform_trusted_operation))
        // To handle when no subcommands match
        .no_cmd(|_args, _matches| {
            println!("No subcommand matched");
            Ok(())
        })
        .run();
    if let Err(e) = res {
        println!("{}", e)
    }
}

fn get_chain_api(matches: &ArgMatches<'_>) -> Api<sr25519::Pair> {
    let url = format!(
        "{}:{}",
        matches.value_of("node-url").unwrap(),
        matches.value_of("node-port").unwrap()
    );
    info!("connecting to {}", url);
    Api::<sr25519::Pair>::new(url)
}

fn get_worker_api(matches: &ArgMatches<'_>) -> WorkerApi {
    let url = format!(
        "{}:{}",
        matches.value_of("worker-url").unwrap(),
        matches.value_of("worker-port").unwrap()
    );
    info!("Connecting to substraTEE-worker on '{}'", url);
    WorkerApi::new(url)
}

fn perform_trusted_operation(
    matches: &ArgMatches<'_>,
    top: &TrustedOperationSigned,
) -> Option<Vec<u8>> {
    match top {
        TrustedOperationSigned::call(call) => send_request(matches, call.clone()),
        TrustedOperationSigned::get(getter) => get_state(matches, getter.clone()),
    }
}

fn get_state(matches: &ArgMatches<'_>, getter: TrustedGetterSigned) -> Option<Vec<u8>> {
    let worker_api = get_worker_api(matches);
    let (_mrenclave, shard) = get_identifiers(matches);
    debug!("calling workerapi to get state value");
    let ret = worker_api
        .get_stf_state(getter, &shard)
        .expect("getting value failed");
    // strip whitespace padding through decoding
    if let Ok(vd) = Decode::decode(&mut ret.as_slice()) {
        debug!("decoded return value: {:?} ", vd);
        vd
    } else {
        debug!("decoding failed");
        None
    }
}

fn send_request(matches: &ArgMatches<'_>, call: TrustedCallSigned) -> Option<Vec<u8>> {
    let chain_api = get_chain_api(matches);
    let worker_api = get_worker_api(matches);
    let shielding_pubkey = worker_api.get_rsa_pubkey().unwrap();

    let call_encoded = call.encode();
    let mut call_encrypted: Vec<u8> = Vec::new();
    shielding_pubkey
        .encrypt_buffer(&call_encoded, &mut call_encrypted)
        .unwrap();

    let arg_signer = matches.value_of("xt-signer").unwrap();
    let signer = get_pair_from_str(arg_signer);
    let _chain_api = chain_api.set_signer(sr25519_core::Pair::from(signer));

    let shard_opt = match matches.value_of("shard") {
        Some(s) => match s.from_base58() {
            Ok(s) => ShardIdentifier::decode(&mut &s[..]),
            _ => panic!("shard argument must be base58 encoded"),
        },
        None => match matches.value_of("mrenclave") {
            Some(m) => match m.from_base58() {
                Ok(s) => ShardIdentifier::decode(&mut &s[..]),
                _ => panic!("mrenclave argument must be base58 encoded"),
            },
            None => panic!("at least one of `mrenclave` or `shard` arguments must be supplied"),
        },
    };
    let shard = match shard_opt {
        Ok(shard) => shard,
        Err(e) => panic!(e),
    };

    let request = Request {
        shard,
        cyphertext: call_encrypted,
    };

    let xt = compose_extrinsic!(_chain_api, "SubstrateeRegistry", "call_worker", request);

    // send and watch extrinsic until finalized
    let tx_hash = _chain_api
        .send_extrinsic(xt.hex_encode(), XtStatus::Ready)
        .unwrap();
    info!("stf call extrinsic sent. Hash: {:?}", tx_hash);
    info!("waiting for confirmation of stf call");
    let (events_in, events_out) = channel();
    _chain_api.subscribe_events(events_in);

    let mut decoder = EventsDecoder::try_from(_chain_api.metadata.clone()).unwrap();
    decoder
        .register_type_size::<Hash>("ShardIdentifier")
        .unwrap();
    decoder.register_type_size::<Hash>("H256").unwrap();

    loop {
        let ret: CallConfirmedArgs = _chain_api
            .wait_for_event(
                "SubstrateeRegistry",
                "CallConfirmed",
                Some(decoder.clone()),
                &events_out,
            )
            .unwrap()
            .unwrap();
        let expected = H256::from(blake2_256(&call_encoded));
        info!("callConfirmed event received");
        debug!("Expected stf call Hash: {:?}", expected);
        debug!("Confirmed stf call Hash: {:?}", ret.payload);
        if ret.payload == expected {
            return Some(ret.payload.encode());
        }
    }
}

#[allow(dead_code)]
#[derive(Decode)]
struct CallConfirmedArgs {
    signer: AccountId,
    payload: H256,
}

fn listen(matches: &ArgMatches<'_>) {
    let api = get_chain_api(matches);
    info!("Subscribing to events");
    let (events_in, events_out) = channel();
    let mut count = 0u32;
    api.subscribe_events(events_in);
    loop {
        if matches.is_present("events")
            && count >= value_t!(matches.value_of("events"), u32).unwrap()
        {
            return;
        };
        let event_str = events_out.recv().unwrap();
        let _unhex = hexstr_to_vec(event_str).unwrap();
        let mut _er_enc = _unhex.as_slice();
        let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
        match _events {
            Ok(evts) => {
                for evr in &evts {
                    debug!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
                    match &evr.event {
                        /*                            Event::balances(be) => {
                            println!(">>>>>>>>>> balances event: {:?}", be);
                            match &be {
                                pallet_balances::RawEvent::Transfer(transactor, dest, value, fee) => {
                                    println!("Transactor: {:?}", transactor);
                                    println!("Destination: {:?}", dest);
                                    println!("Value: {:?}", value);
                                    println!("Fee: {:?}", fee);
                                }
                                _ => {
                                    debug!("ignoring unsupported balances event");
                                }
                            }
                        },*/
                        Event::substratee_registry(ee) => {
                            println!(">>>>>>>>>> substraTEE event: {:?}", ee);
                            count += 1;
                            match &ee {
                                substratee_node_runtime::substratee_registry::RawEvent::AddedEnclave(accountid, url) => {
                                    println!("AddedEnclave: {:?} at url {}", accountid, String::from_utf8(url.to_vec()).unwrap_or_else(|_| "error".to_string()));
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::RemovedEnclave(accountid) => {
                                    println!("RemovedEnclave: {:?}", accountid);
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::UpdatedIpfsHash(shard, idx, ipfs_hash) => {
                                    println!("UpdatedIpfsHash for shard {}, worker index {}, ipfs# {:?}", shard.encode().to_base58(), idx, ipfs_hash);
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::Forwarded(request) => {
                                    let request_hash = hex::encode(request.cyphertext.clone());
                                    println!("Forwarded request for shard {}: {}", request.shard.encode().to_base58(), request_hash);
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::CallConfirmed(accountid, call_hash) => {
                                    println!("CallConfirmed from {} with hash {:?}", accountid, call_hash);
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::ShieldFunds(incognito_account) => {
                                    println!("ShieldFunds for {:?}", incognito_account);
                                },
                                substratee_node_runtime::substratee_registry::RawEvent::UnshieldedFunds(public_account) => {
                                    println!("UnshieldFunds for {:?}", public_account);
                                },
                            }
                        }
                        _ => debug!("ignoring unsupported module event: {:?}", evr.event),
                    }
                }
            }
            Err(_) => error!("couldn't decode event record list"),
        }
    }
}

// subscribes to he substratee_registry events of type CallConfirmed
pub fn subscribe_to_call_confirmed<P: Pair>(api: Api<P>) -> H256
where
    MultiSignature: From<P::Signature>,
{
    let (events_in, events_out) = channel();

    let _eventsubscriber = thread::Builder::new()
        .name("eventsubscriber".to_owned())
        .spawn(move || {
            api.subscribe_events(events_in.clone());
        })
        .unwrap();

    println!("waiting for confirmation event...");
    loop {
        let event_str = events_out.recv().unwrap();

        let _unhex = hexstr_to_vec(event_str).unwrap();
        let mut _er_enc = _unhex.as_slice();
        let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
        if let Ok(evts) = _events {
            for evr in &evts {
                info!("received event {:?}", evr.event);
                if let Event::substratee_registry(pe) = &evr.event {
                    if let substratee_node_runtime::substratee_registry::RawEvent::CallConfirmed(
                        sender,
                        payload,
                    ) = &pe
                    {
                        println!("[+] Received confirm call from {}", sender);
                        return payload.clone().to_owned();
                    } else {
                        debug!(
                            "received unknown event from SubstraTeeRegistry: {:?}",
                            evr.event
                        )
                    }
                }
            }
        }
    }
}

fn get_accountid_from_str(account: &str) -> AccountId {
    match &account[..2] {
        "//" => AccountPublic::from(sr25519::Pair::from_string(account, None).unwrap().public())
            .into_account(),
        _ => AccountPublic::from(sr25519::Public::from_ss58check(account).unwrap()).into_account(),
    }
}

// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(account: &str) -> sr25519::AppPair {
    info!("getting pair for {}", account);
    match &account[..2] {
        "//" => sr25519::AppPair::from_string(account, None).unwrap(),
        _ => {
            info!("fetching from keystore at {}", &KEYSTORE_PATH);
            // open store without password protection
            let store =
                Store::open(PathBuf::from(&KEYSTORE_PATH), None).expect("store should exist");
            info!("store opened");
            let _pair = store
                .read()
                .key_pair::<sr25519::AppPair>(
                    &sr25519::Public::from_ss58check(account).unwrap().into(),
                )
                .unwrap();
            drop(store);
            _pair
        }
    }
}

fn get_enclave_count(api: &Api<sr25519::Pair>) -> u64 {
    if let Some(count) = api.get_storage_value("SubstrateeRegistry", "EnclaveCount", None) {
        count
    } else {
        0
    }
}

fn get_enclave(api: &Api<sr25519::Pair>, eindex: u64) -> Option<Enclave<AccountId, Vec<u8>>> {
    api.get_storage_map("SubstrateeRegistry", "EnclaveRegistry", eindex, None)
}
