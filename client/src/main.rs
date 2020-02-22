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
#[macro_use] 
extern crate log;
extern crate env_logger;

extern crate chrono;
use chrono::{DateTime, Utc};
use std::time::{SystemTime, UNIX_EPOCH, Duration};

use keyring::AccountKeyring;
use keystore::Store;
use std::path::PathBuf;
use app_crypto::{AppKey, AppPublic, AppPair, ed25519, sr25519};

use substrate_api_client::{
    Api, node_metadata,
    compose_extrinsic,
    extrinsic, 
    extrinsic::xt_primitives::{UncheckedExtrinsicV4, GenericAddress},
    rpc::json_req,
    utils::{storage_key_hash, hexstr_to_hash, hexstr_to_u256, hexstr_to_u64, hexstr_to_vec},
};
use codec::{Encode, Decode};
use primitives::{
	crypto::{set_default_ss58_version, Ss58AddressFormat, Ss58Codec},
	Pair, sr25519 as sr25519_core, Public, H256, hexdisplay::HexDisplay,
};
use bip39::{Mnemonic, Language, MnemonicType};
use base58::{FromBase58, ToBase58};
use substratee_node_runtime::{AccountId, Event, Call, SubstraTEERegistryCall, BalancesCall, 
    Signature, Hash,
    substratee_registry::{Enclave, ShardIdentifier, Request}
}; 
use sr_primitives::traits::{Verify, IdentifyAccount};

use serde_json;
use log::{info, debug, trace, warn};
use log::Level;
use clap::App;
use std::sync::mpsc::channel;
use std::collections::HashMap;

type AccountPublic = <Signature as Verify>::Signer;
const KEYSTORE_PATH: &str = "my_keystore";
const PREFUNDING_AMOUNT: u128 = 1_000_000_000;

fn main() {
    env_logger::init();
    let yml = load_yaml!("cli.yml");
	let matches = App::from_yaml(yml).get_matches();

	let url = matches.value_of("URL").expect("must specify URL");
	info!("connecting to {}", url);
    let api = Api::<sr25519::Pair>::new(format!("ws://{}", url));
    
    if let Some(_matches) = matches.subcommand_matches("print_metadata") {
        let meta = api.get_metadata();
        println!(
            "Metadata:\n {}",
            node_metadata::pretty_format(&meta).unwrap()
        );
    }

    if let Some(_matches) = matches.subcommand_matches("new-account") {
        // open store without password protection
        let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
        let key: sr25519::AppPair = store.write().generate().unwrap();
        drop(store);
        println!("{}", key.public().to_ss58check())
    }

    if let Some(_matches) = matches.subcommand_matches("fund-account") {
        let account = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(account);

        let _api = api.clone().set_signer(AccountKeyring::Alice.pair());
        let xt = _api.balance_transfer(GenericAddress::from(accountid.clone()), PREFUNDING_AMOUNT);
        info!("[+] Alice is generous and pre funds account {}\n", accountid.to_ss58check()); 
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        info!("[+] Pre-Funding transaction got finalized. Hash: {:?}\n", tx_hash);
        let result = _api.get_free_balance(&accountid.clone());
        println!("balance for {} is now {}", accountid.to_ss58check(), result);
    }

    if let Some(_matches) = matches.subcommand_matches("list-accounts") {
        let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).unwrap();
        println!("sr25519 keys:");
        for pubkey in store.read().public_keys::<sr25519::AppPublic>().unwrap().into_iter() {
            println!("{}",pubkey.to_ss58check());
        }
        println!("ed25519 keys:");
        for pubkey in store.read().public_keys::<ed25519::AppPublic>().unwrap().into_iter() {
            println!("{}",pubkey.to_ss58check());
        }
        drop(store);
    }

    if let Some(_matches) = matches.subcommand_matches("balance") {
        let account = _matches.value_of("account").unwrap();
        let accountid = get_accountid_from_str(account);
        let result_str = api
            .get_storage("Balances", "FreeBalance", Some(accountid.encode()))
            .unwrap();
        let result = hexstr_to_u256(result_str).unwrap();
        info!("ss58 is {}", accountid.to_ss58check());
        println!("balance for {} is {}", account, result);
    }

    if let Some(_matches) = matches.subcommand_matches("transfer") {
        let arg_from = _matches.value_of("from").unwrap();
        let arg_to = _matches.value_of("to").unwrap();
        let amount = u128::from_str_radix(_matches.value_of("amount").unwrap(),10).expect("amount can be converted to u128");
        let from = get_pair_from_str(arg_from);
        let to = get_accountid_from_str(arg_to);
        info!("from ss58 is {}", from.public().to_ss58check());
        info!("to ss58 is {}", to.to_ss58check());
        let _api = api.clone().set_signer(sr25519_core::Pair::from(from));
        let xt = _api.balance_transfer(GenericAddress::from(to.clone()), amount);
        let tx_hash = _api.send_extrinsic(xt.hex_encode()).unwrap();
        println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);
        let result = _api.get_free_balance(&to);
        println!("balance for {} is now {}", to, result);
    }

    if let Some(_matches) = matches.subcommand_matches("list-workers") {
        let wcount = get_enclave_count(&api);
        println!("number of workers registered: {}", wcount);
        for w in 1..wcount+1 {
            let enclave = get_enclave(&api, w);
            if enclave.is_none() {
                println!("error reading enclave data");
                continue;
            };
            let enclave = enclave.unwrap();
            let timestamp = DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(enclave.timestamp as u64));
            println!("Enclave {}", w);
            println!("   AccountId: {}", enclave.pubkey.to_ss58check());
            println!("   MRENCLAVE: {}", enclave.mr_enclave.to_base58());
            println!("   RA timestamp: {}", timestamp);
            println!("   URL: {}", String::from_utf8(enclave.url).unwrap());
        }
    }

    if let Some(_matches) = matches.subcommand_matches("listen") {
        info!("Subscribing to events");
        let (events_in, events_out) = channel();
        api.subscribe_events(events_in.clone());
        loop {
            let event_str = events_out.recv().unwrap();
            let _unhex = hexstr_to_vec(event_str).unwrap();
            let mut _er_enc = _unhex.as_slice();
            let _events = Vec::<system::EventRecord<Event, Hash>>::decode(&mut _er_enc);
            match _events {
                Ok(evts) => {
                    for evr in &evts {
                        debug!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
                        match &evr.event {
/*                            Event::balances(be) => {
                                println!(">>>>>>>>>> balances event: {:?}", be);
                                match &be {
                                    balances::RawEvent::Transfer(transactor, dest, value, fee) => {
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
                                println!(">>>>>>>>>> ceremony event: {:?}", ee);
                                match &ee {
                                    substratee_node_runtime::substratee_registry::RawEvent::AddedEnclave(accountid, url) => {
                                        println!("AddedEnclave: {:?} at url {}", accountid, String::from_utf8(url.to_vec()).unwrap_or("error".to_string()));
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
                                    _ => {
                                        debug!("ignoring unsupported substraTEE event");
                                    }
                                }
                            },
                            _ => debug!("ignoring unsupported module event: {:?}", evr.event),
                        }
                    }
                }
                Err(_) => error!("couldn't decode event record list"),
            }
        }
    }
}

fn get_accountid_from_str(account: &str) -> AccountId {
    match &account[..2] {
        "//" => AccountPublic::from(sr25519::Pair::from_string(account, None)
            .unwrap().public()).into_account(),
        _ => AccountPublic::from(sr25519::Public::from_ss58check(account)
            .unwrap()).into_account(),
    }
}

// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(account: &str) ->sr25519::AppPair {
    info!("getting pair for {}", account);
    match &account[..2] {
        "//" => sr25519::AppPair::from_string(account, None).unwrap(),
        _ => {
            info!("fetching from keystore at {}", &KEYSTORE_PATH);
            // open store without password protection
            let store = Store::open(PathBuf::from(&KEYSTORE_PATH), None).expect("store should exist");
            info!("store opened");
            let _pair = store.read().key_pair::<sr25519::AppPair>(&sr25519::Public::from_ss58check(account).unwrap().into()).unwrap();
            drop(store);
            _pair
        }
            
    }
}

fn get_enclave_count(api: &Api<sr25519::Pair>) -> u64 {
    hexstr_to_u64(api
            .get_storage("substraTEERegistry", "EnclaveCount", None)
            .unwrap()
            ).unwrap() 
}

fn get_enclave(
    api: &Api<sr25519::Pair>, 
    eindex: u64, 
    ) -> Option<Enclave<AccountId, Vec<u8>>> 
{
    let res = api
        .get_storage("substraTEERegistry", "EnclaveRegistry", 
            Some(eindex.encode())).unwrap();
    match res.as_str() {
        "null" => None,
        _ => {
            let enclave: Enclave<AccountId, Vec<u8>> = Decode::decode(
                &mut &hexstr_to_vec(res).unwrap()[..]).unwrap();
            Some(enclave)
        }
    }
}

