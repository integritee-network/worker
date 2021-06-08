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

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

use sp_application_crypto::{ed25519, sr25519};
use sp_keyring::AccountKeyring;
use std::path::PathBuf;

use base58::{FromBase58, ToBase58};

use clap::{AppSettings, Arg, ArgMatches};
use clap_nested::{Command, Commander};
use codec::{Decode, Encode};
use log::*;
use my_node_runtime::{
    substratee_registry::Request,
    AccountId, BalancesCall, Call, Event, Hash, Signature,
};

use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair, H256};
use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};
use std::convert::TryFrom;
use std::result::Result as StdResult;
use std::sync::mpsc::channel;
use std::thread;
use substrate_api_client::{
    compose_extrinsic, compose_extrinsic_offline,
    events::EventsDecoder,
    extrinsic::xt_primitives::{GenericAddress, UncheckedExtrinsicV4},
    node_metadata::Metadata,
    utils::FromHexString,
    Api, XtStatus,
};

use substrate_client_keystore::LocalKeystore;
use substratee_stf::{ShardIdentifier, TrustedCallSigned, TrustedOperation};
use substratee_worker_api::direct_client::DirectApi as DirectWorkerApi;
use substratee_api_client_extensions::SubstrateeRegistryApi;
use substratee_worker_primitives::{DirectRequestStatus, RpcRequest, RpcResponse, RpcReturnValue};

type AccountPublic = <Signature as Verify>::Signer;
const KEYSTORE_PATH: &str = "my_keystore";
const PREFUNDING_AMOUNT: u128 = 1_000_000_000;
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    env_logger::init();

    let res = Commander::new()
        .options(|app| {
            app.setting(AppSettings::ColoredHelp)
            .arg(
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
                Arg::with_name("worker-rpc-port")
                    .short("P")
                    .long("worker-rpc-port")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("2000")
                    .help("worker direct invocation port"),
            )
            .name("substratee-client")
            .version(VERSION)
            .author("Supercomputing Systems AG <info@scs.ch>")
            .about("interact with substratee-node and workers")
            .after_help("stf subcommands depend on the stf crate this has been built against")
        })
        .args(|_args, matches| matches.value_of("environment").unwrap_or("dev"))
        .add_cmd(
            Command::new("new-account")
                .description("generates a new account for the substraTEE chain")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    let key: sr25519::AppPair = store.generate().unwrap();
                    drop(store);
                    println!("{}", key.public().to_ss58check());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-accounts")
                .description("lists all accounts in keystore for the substraTEE chain")
                .runner(|_args: &str, _matches: &ArgMatches<'_>| {
                    let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
                    println!("sr25519 keys:");
                    for pubkey in store
                        .public_keys::<sr25519::AppPublic>()
                        .unwrap()
                        .into_iter()
                    {
                        println!("{}", pubkey.to_ss58check());
                    }
                    println!("ed25519 keys:");
                    for pubkey in store
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
                    let meta = get_chain_api(matches).get_metadata().unwrap();
                    println!("Metadata:\n {}", Metadata::pretty_format(&meta).unwrap());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("faucet")
                .description("send some bootstrapping funds to supplied account(s)")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp).arg(
                        Arg::with_name("accounts")
                            .takes_value(true)
                            .required(true)
                            .value_name("ACCOUNT")
                            .multiple(true)
                            .min_values(1)
                            .help("Account(s) to be funded, ss58check encoded"),
                    )
                })
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let _api = api.set_signer(AccountKeyring::Alice.pair());
                    let accounts: Vec<_> = matches.values_of("accounts").unwrap().collect();

                    let mut nonce = _api.get_nonce().unwrap();
                    for account in accounts.into_iter() {
                        let to = get_accountid_from_str(account);
                        #[allow(clippy::redundant_clone)]
                        let xt: UncheckedExtrinsicV4<_> = compose_extrinsic_offline!(
                            _api.clone().signer.unwrap(),
                            Call::Balances(BalancesCall::transfer(
                                GenericAddress::Id(to.clone()),
                                PREFUNDING_AMOUNT
                            )),
                            nonce,
                            Era::Immortal,
                            _api.genesis_hash,
                            _api.genesis_hash,
                            _api.runtime_version.spec_version,
                            _api.runtime_version.transaction_version
                        );
                        // send and watch extrinsic until finalized
                        println!("Faucet drips to {} (Alice's nonce={})", to, nonce);
                        let _blockh = _api
                            .send_extrinsic(xt.hex_encode(), XtStatus::Ready)
                            .unwrap();
                        nonce += 1;
                    }
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("balance")
                .description("query on-chain balance for AccountId")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp).arg(
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
                    let balance = if let Some(data) = api.get_account_data(&accountid).unwrap() {
                        data.free
                    } else {
                        0
                    };
                    println!("{}", balance);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("transfer")
                .description("transfer funds from one on-chain account to another")
                .options(|app| {
                    app.setting(AppSettings::ColoredHelp)
                        .arg(
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
                    let xt = _api.balance_transfer(GenericAddress::Id(to.clone()), amount);
                    let tx_hash = _api
                        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
                        .unwrap();
                    println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);
                    let result = _api.get_account_data(&to).unwrap().unwrap();
                    println!("balance for {} is now {}", to, result.free);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-workers")
                .description("query enclave registry and list all workers")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let api = get_chain_api(matches);
                    let wcount = api.enclave_count().unwrap();
                    println!("number of workers registered: {}", wcount);
                    for w in 1..=wcount {
                        let enclave = api.enclave(w).unwrap();
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
                    app.setting(AppSettings::ColoredHelp)
                        .arg(
                            Arg::with_name("events")
                                .short("e")
                                .long("exit-after")
                                .takes_value(true)
                                .help("exit after given number of SubstraTEE events"),
                        )
                        .arg(
                            Arg::with_name("blocks")
                                .short("b")
                                .long("await-blocks")
                                .takes_value(true)
                                .help("exit after given number of blocks"),
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
                        Err(e) => panic!("{}", e),
                    };

                    // get the sender
                    let arg_from = matches.value_of("from").unwrap();
                    let from = get_pair_from_str(arg_from);
                    let chain_api = chain_api.set_signer(sr25519_core::Pair::from(from));

                    // get the recipient
                    let arg_to = matches.value_of("to").unwrap();
                    let to = get_accountid_from_str(arg_to);
                    let (_to_encoded, to_encrypted) = match encode_encrypt(matches, to){
                        Ok((encoded, encrypted)) => (encoded, encrypted),
                        Err(e) => panic!("{}", e)
                    };
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
                    println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);
                    Ok(())
                }),
        )
        .add_cmd(substratee_stf::cli::cmd(&perform_trusted_operation))
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
    Api::<sr25519::Pair>::new(url).unwrap()
}

fn perform_trusted_operation(matches: &ArgMatches<'_>, top: &TrustedOperation) -> Option<Vec<u8>> {
    match top {
        TrustedOperation::indirect_call(call) => send_request(matches, call.clone()),
        TrustedOperation::direct_call(call) => {
            send_direct_request(matches, TrustedOperation::direct_call(call.clone()))
        }
        TrustedOperation::get(getter) => get_state(matches, TrustedOperation::get(getter.clone())),
    }
}

fn get_state(matches: &ArgMatches<'_>, getter: TrustedOperation) -> Option<Vec<u8>> {
    // TODO: ensure getter is signed?
    let (_operation_call_encoded, operation_call_encrypted) = match encode_encrypt(matches, getter)
    {
        Ok((encoded, encrypted)) => (encoded, encrypted),
        Err(msg) => {
            println!("[Error] {}", msg);
            return None;
        }
    };
    let shard = read_shard(matches).unwrap();

    // compose jsonrpc call
    let data = Request {
        shard,
        cyphertext: operation_call_encrypted,
    };
    let rpc_method = "author_submitAndWatchExtrinsic".to_owned();
    let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(rpc_method, data.encode());

    let direct_api = get_worker_api_direct(matches);
    let (sender, receiver) = channel();
    match direct_api.watch(jsonrpc_call, sender) {
        Ok(_) => {}
        Err(_) => panic!("Error when sending direct invocation call"),
    }

    loop {
        match receiver.recv() {
            Ok(response) => {
                let response: RpcResponse = serde_json::from_str(&response).unwrap();
                if let Ok(return_value) = RpcReturnValue::decode(&mut response.result.as_slice()) {
                    if return_value.status == DirectRequestStatus::Error {
                        println!(
                            "[Error] {}",
                            String::decode(&mut return_value.value.as_slice()).unwrap()
                        );
                        return None;
                    }
                    if !return_value.do_watch {
                        return match Option::decode(&mut return_value.value.as_slice()) {
                            Ok(value_opt) => value_opt,
                            Err(_) => panic!("Error when decoding response"),
                        };
                    }
                };
            }
            Err(_) => return None,
        };
    }
}

fn encode_encrypt<E: Encode>(
    matches: &ArgMatches<'_>,
    to_encrypt: E,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let worker_api_direct = get_worker_api_direct(matches);
    let shielding_pubkey: Rsa3072PubKey = match worker_api_direct.get_rsa_pubkey() {
        Ok(key) => key,
        Err(err_msg) => return Err(err_msg),
    };

    let encoded = to_encrypt.encode();
    let mut encrypted: Vec<u8> = Vec::new();
    shielding_pubkey
        .encrypt_buffer(&encoded, &mut encrypted)
        .unwrap();
    Ok((encoded, encrypted))
}

fn send_request(matches: &ArgMatches<'_>, call: TrustedCallSigned) -> Option<Vec<u8>> {
    let chain_api = get_chain_api(matches);
    let (_, call_encrypted) = match encode_encrypt(matches, call) {
        Ok((encoded, encrypted)) => (encoded, encrypted),
        Err(msg) => {
            println!("[Error]: {}", msg);
            return None;
        }
    };

    let shard = read_shard(matches).unwrap();

    let arg_signer = matches.value_of("xt-signer").unwrap();
    let signer = get_pair_from_str(arg_signer);
    let _chain_api = chain_api.set_signer(sr25519_core::Pair::from(signer));

    let request = Request {
        shard,
        cyphertext: call_encrypted,
    };
    let xt = compose_extrinsic!(_chain_api, "SubstrateeRegistry", "call_worker", request);

    // send and watch extrinsic until block is executed
    let block_hash = _chain_api
        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap()
        .unwrap();
    info!("stf call extrinsic sent. Block Hash: {:?}", block_hash);
    info!("waiting for confirmation of stf call");
    let (events_in, events_out) = channel();
    _chain_api.subscribe_events(events_in).unwrap();

    let mut decoder = EventsDecoder::try_from(_chain_api.metadata.clone()).unwrap();
    decoder
        .register_type_size::<Hash>("ShardIdentifier")
        .unwrap();
    decoder.register_type_size::<Hash>("H256").unwrap();

    loop {
        let ret: BlockConfirmedArgs = _chain_api
            .wait_for_event::<BlockConfirmedArgs>(
                "SubstrateeRegistry",
                "BlockConfirmed",
                Some(decoder.clone()),
                &events_out,
            )
            .unwrap();
        info!("BlockConfirmed event received");
        debug!("Expected stf block Hash: {:?}", block_hash);
        debug!("Confirmed stf block Hash: {:?}", ret.payload);
        if ret.payload == block_hash {
            return Some(ret.payload.encode());
        }
    }
}

fn get_worker_api_direct(matches: &ArgMatches<'_>) -> DirectWorkerApi {
    let url = format!(
        "{}:{}",
        matches.value_of("worker-url").unwrap(),
        matches.value_of("worker-rpc-port").unwrap()
    );
    info!("Connecting to substraTEE-worker-direct-port on '{}'", url);
    DirectWorkerApi::new(url)
}

fn read_shard(matches: &ArgMatches<'_>) -> StdResult<ShardIdentifier, codec::Error> {
    match matches.value_of("shard") {
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
    }
}
/// sends a rpc watch request to the worker api server
fn send_direct_request(
    matches: &ArgMatches<'_>,
    operation_call: TrustedOperation,
) -> Option<Vec<u8>> {
    let (_operation_call_encoded, operation_call_encrypted) =
        match encode_encrypt(matches, operation_call) {
            Ok((encoded, encrypted)) => (encoded, encrypted),
            Err(msg) => {
                println!("[Error] {}", msg);
                return None;
            }
        };
    let shard = read_shard(matches).unwrap();

    // compose jsonrpc call
    let data = Request {
        shard,
        cyphertext: operation_call_encrypted,
    };
    let direct_invocation_call = RpcRequest {
        jsonrpc: "2.0".to_owned(),
        method: "author_submitAndWatchExtrinsic".to_owned(),
        params: data.encode(),
        id: 1,
    };
    let jsonrpc_call: String = serde_json::to_string(&direct_invocation_call).unwrap();

    let direct_api = get_worker_api_direct(matches);
    let (sender, receiver) = channel();
    match direct_api.watch(jsonrpc_call, sender) {
        Ok(_) => {}
        Err(_) => panic!("Error when sending direct invocation call"),
    }

    loop {
        match receiver.recv() {
            Ok(response) => {
                let response: RpcResponse = serde_json::from_str(&response).unwrap();
                if let Ok(return_value) = RpcReturnValue::decode(&mut response.result.as_slice()) {
                    match return_value.status {
                        DirectRequestStatus::Error => {
                            if let Ok(value) = String::decode(&mut return_value.value.as_slice()) {
                                println!("[Error] {}", value);
                            }
                            return None;
                        }
                        DirectRequestStatus::TrustedOperationStatus(status) => {
                            if let Ok(value) = Hash::decode(&mut return_value.value.as_slice()) {
                                println!("Trusted call {:?} is {:?}", value, status);
                            }
                        }
                        _ => return None,
                    }
                    if !return_value.do_watch {
                        return None;
                    }
                };
            }
            Err(_) => return None,
        };
    }
}

#[allow(dead_code)]
#[derive(Decode)]
struct BlockConfirmedArgs {
    signer: AccountId,
    payload: H256,
}

fn listen(matches: &ArgMatches<'_>) {
    let api = get_chain_api(matches);
    info!("Subscribing to events");
    let (events_in, events_out) = channel();
    let mut count = 0u32;
    let mut blocks = 0u32;
    api.subscribe_events(events_in).unwrap();
    loop {
        if matches.is_present("events")
            && count >= value_t!(matches.value_of("events"), u32).unwrap()
        {
            return;
        };
        if matches.is_present("blocks")
            && blocks > value_t!(matches.value_of("blocks"), u32).unwrap()
        {
            return;
        };
        let event_str = events_out.recv().unwrap();
        let _unhex = Vec::from_hex(event_str).unwrap();
        let mut _er_enc = _unhex.as_slice();
        let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
        blocks += 1;
        match _events {
            Ok(evts) => {
                for evr in &evts {
                    println!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
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
                                my_node_runtime::substratee_registry::RawEvent::AddedEnclave(
                                    accountid,
                                    url,
                                ) => {
                                    println!(
                                        "AddedEnclave: {:?} at url {}",
                                        accountid,
                                        String::from_utf8(url.to_vec())
                                            .unwrap_or_else(|_| "error".to_string())
                                    );
                                }
                                my_node_runtime::substratee_registry::RawEvent::RemovedEnclave(
                                    accountid,
                                ) => {
                                    println!("RemovedEnclave: {:?}", accountid);
                                }
                                my_node_runtime::substratee_registry::RawEvent::UpdatedIpfsHash(
                                    shard,
                                    idx,
                                    ipfs_hash,
                                ) => {
                                    println!(
                                        "UpdatedIpfsHash for shard {}, worker index {}, ipfs# {:?}",
                                        shard.encode().to_base58(),
                                        idx,
                                        ipfs_hash
                                    );
                                }
                                my_node_runtime::substratee_registry::RawEvent::Forwarded(
                                    shard,
                                ) => {
                                    println!(
                                        "Forwarded request for shard {}",
                                        shard.encode().to_base58()
                                    );
                                }
                                my_node_runtime::substratee_registry::RawEvent::CallConfirmed(
                                    accountid,
                                    call_hash,
                                ) => {
                                    println!(
                                        "CallConfirmed from {} with hash {:?}",
                                        accountid, call_hash
                                    );
                                }
                                my_node_runtime::substratee_registry::RawEvent::BlockConfirmed(
                                    accountid,
                                    block_hash,
                                ) => {
                                    println!(
                                        "BlockConfirmed from {} with hash {:?}",
                                        accountid, block_hash
                                    );
                                }
                                my_node_runtime::substratee_registry::RawEvent::ShieldFunds(
                                    incognito_account,
                                ) => {
                                    println!("ShieldFunds for {:?}", incognito_account);
                                }
                                my_node_runtime::substratee_registry::RawEvent::UnshieldedFunds(
                                    public_account,
                                ) => {
                                    println!("UnshieldFunds for {:?}", public_account);
                                }
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
            api.subscribe_events(events_in.clone()).unwrap();
        })
        .unwrap();

    println!("waiting for confirmation event...");
    loop {
        let event_str = events_out.recv().unwrap();

        let _unhex = Vec::from_hex(event_str).unwrap();
        let mut _er_enc = _unhex.as_slice();
        let _events = Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
        if let Ok(evts) = _events {
            for evr in &evts {
                info!("received event {:?}", evr.event);
                if let Event::substratee_registry(pe) = &evr.event {
                    if let my_node_runtime::substratee_registry::RawEvent::CallConfirmed(
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
            let store = LocalKeystore::open(PathBuf::from(&KEYSTORE_PATH), None)
                .expect("store should exist");
            info!("store opened");
            let _pair = store
                .key_pair::<sr25519::AppPair>(
                    &sr25519::Public::from_ss58check(account).unwrap().into(),
                )
                .unwrap();
            drop(store);
            _pair
        }
    }
}
