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

use crate::{AccountId, ShardIdentifier, TrustedCall, TrustedGetter, PublicGetter, TrustedOperation, Attestation};
use base58::{FromBase58, ToBase58};
use clap::{Arg, ArgMatches};
use clap_nested::{Command, Commander, MultiCommand};
use codec::{Decode, Encode};
use log::*;
use sc_keystore::Store;
use sp_application_crypto::{ed25519, sr25519};
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use sp_runtime::traits::IdentifyAccount;
use std::path::PathBuf;
use fixed::traits::LossyInto;
use fixed::transcendental::exp;
use my_node_runtime::{BlockNumber, Header};
use encointer_balances::{BalanceType, BalanceEntry};
use encointer_currencies::{Location, CurrencyIdentifier, CurrencyPropertiesType};
use encointer_ceremonies::{MeetupIndexType, ClaimOfAttendance, ParticipantIndexType};
use hex;
use substrate_api_client::Api;
use sp_runtime::{MultiSignature, AccountId32};

type Moment = u64;

const KEYSTORE_PATH: &str = "my_trusted_keystore";

pub fn cmd<'a>(
    perform_operation: &'a dyn Fn(&ArgMatches<'_>, &TrustedOperation) -> Option<Vec<u8>>,
) -> MultiCommand<'a, str, str> {
    Commander::new()
        .options(|app| {
            app.arg(
                Arg::with_name("mrenclave")
                    .short("m")
                    .long("mrenclave")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .help("targeted worker MRENCLAVE"),
            )
            .arg(
                Arg::with_name("shard")
                    .short("s")
                    .long("shard")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .help("shard identifier"),
            )
            .arg(
                Arg::with_name("xt-signer")
                    .short("a")
                    .long("xt-signer")
                    .global(true)
                    .takes_value(true)
                    .value_name("AccountId")
                    .default_value("//Alice")
                    .help("signer for publicly observable extrinsic"),
            )
            .about("trusted calls to worker enclave")
        })
        .add_cmd(
            Command::new("new-account")
                .description("generates a new incognito account for the given substraTEE shard")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let store = Store::open(get_keystore_path(matches), None).unwrap();
                    let key: sr25519::AppPair = store.write().generate().unwrap();
                    drop(store);
                    println!("{}", key.public().to_ss58check());
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("list-accounts")
                .description("lists all accounts in keystore for the substraTEE chain")
                .runner(|_args: &str, matches: &ArgMatches<'_>| {
                    let store = Store::open(get_keystore_path(matches), None).unwrap();
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
            Command::new("transfer")
                .description("send funds from one incognito account to another")
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
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_from = matches.value_of("from").unwrap();
                    let arg_to = matches.value_of("to").unwrap();
                    let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                        .expect("amount can be converted to u128");
                    let from = get_pair_from_str(matches, arg_from);
                    let to = get_accountid_from_str(arg_to);
                    info!("from ss58 is {}", from.public().to_ss58check());
                    info!("to ss58 is {}", to.to_ss58check());

                    println!(
                        "send trusted call transfer from {} to {}: {}",
                        from.public(),
                        to,
                        amount
                    );
                    let (mrenclave, shard) = get_identifiers(matches);
                    let nonce = 0; // FIXME: hard coded for now
                    let top: TrustedOperation = TrustedCall::balance_transfer(
                        sr25519_core::Public::from(from.public()),
                        to,
                        shard, // for encointer we assume that every currency has its own shard. so shard == cid
                        BalanceType::from_num(amount))
                        .sign(&sr25519_core::Pair::from(from), nonce, &mrenclave, &shard)
                        .into();
                    let _ = perform_operation(matches, &top);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("balance")
                .description("query balance for incognito account in keystore")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    println!("arg_who = {:?}", arg_who);
                    let who = get_pair_from_str(matches, arg_who);
                    let (_mrenclave, shard) = get_identifiers(matches);
                    let top: TrustedOperation = TrustedGetter::balance(sr25519_core::Public::from(who.public()), shard)
                        .sign(&sr25519_core::Pair::from(who))
                        .into();
                    let res = perform_operation(matches, &top);
                    let bal = if let Some(v) = res {
                        if let Ok(vd) = <BalanceEntry<BlockNumber>>::decode(&mut v.as_slice()) {
                            let api = get_chain_api(matches);
                            let bn = get_block_number(&api);
                            let dr = get_demurrage_per_block(&api, shard);
                            debug!("will apply demurrage to {:?}. blocknumber {}, demurrage rate {}", vd, bn, dr);
                            apply_demurrage(vd, bn, dr)
                        } else {
                            info!("could not decode value. maybe hasn't been set? {:x?}", v);
                            BalanceType::from_num(0)
                        }
                    } else {
                        BalanceType::from_num(0)
                    };
                    println!("{}", bal);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("info")
                .description("query various statistics and settings for a currency (public information)")
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let (_mrenclave, shard) = get_identifiers(matches);
                    println!("Public information about currency {}", shard.encode().to_base58());
                    let top: TrustedOperation = PublicGetter::total_issuance(shard)
                        .into();
                    let res = perform_operation(matches, &top);
                    let bal = if let Some(v) = res {
                        if let Ok(vd) = <BalanceEntry<BlockNumber>>::decode(&mut v.as_slice()) {
                            let api = get_chain_api(matches);
                            let bn = get_block_number(&api);
                            let dr = get_demurrage_per_block(&api, shard);
                            debug!("will apply demurrage to {:?}. blocknumber {}, demurrage rate {}", vd, bn, dr);
                            apply_demurrage(vd, bn, dr)                            
                        } else {
                            info!("could not decode value. maybe hasn't been set? {:x?}", v);
                            BalanceType::from_num(0)
                        }
                    } else {
                        BalanceType::from_num(0)
                    };
                    println!("  total issuance: {}", bal);

                    let top: TrustedOperation = PublicGetter::participant_count(shard)
                        .into();
                    if let Some(v) = perform_operation(matches, &top) {
                        if let Ok(vd) = ParticipantIndexType::decode(&mut v.as_slice()) {
                            println!("  participant count: {}", vd);
                        } else { println!("  participant count: error decoding"); }
                    } else { println!("  participant count: undisclosed (might be REGISTERING phase?)"); };
                    
                    let top: TrustedOperation = PublicGetter::meetup_count(shard)
                        .into();
                    if let Some(v) = perform_operation(matches, &top) {
                        if let Ok(vd) = MeetupIndexType::decode(&mut v.as_slice()) {
                            println!("  meetup count: {}", vd);
                        } else { println!("  meetup count: error decoding"); }
                    } else { println!("  meetup count: unknown"); };

                    let top: TrustedOperation = PublicGetter::ceremony_reward(shard)
                        .into();
                    if let Some(v) = perform_operation(matches, &top) {
                        if let Ok(vd) = BalanceType::decode(&mut v.as_slice()) {
                            println!("  ceremony reward: {}", vd);
                        } else { println!("  ceremony reward: error decoding"); }
                    } else { println!("  ceremony reward: unknown"); };

                    let top: TrustedOperation = PublicGetter::location_tolerance(shard)
                        .into();
                    if let Some(v) = perform_operation(matches, &top) {
                        if let Ok(vd) = u32::decode(&mut v.as_slice()) {
                            println!("  location tolerance: {}m", vd);
                        } else { println!("  location tolerance: error decoding"); }
                    } else { println!("  location tolerance: unknown"); };

                    let top: TrustedOperation = PublicGetter::time_tolerance(shard)
                        .into();
                    if let Some(v) = perform_operation(matches, &top) {
                        if let Ok(vd) = Moment::decode(&mut v.as_slice()) {
                            println!("  time tolerance: {}m", vd);
                        } else { println!("  time tolerance: unknown nodecode"); }
                    } else { println!("  time tolerance: unknown"); };

                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("register-participant")
                .description("register participant for next encointer ceremony")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let who = get_pair_from_str(matches, arg_who);
                    let (mrenclave, shard) = get_identifiers(matches);
                    let nonce = 0; // FIXME: hard coded for now
                    println!(
                        "send TrustedCall::register_participant for {}",
                        who.public(),
                    );
                    let top: TrustedOperation = TrustedCall::ceremonies_register_participant(
                        sr25519_core::Public::from(who.public()),
                        shard, // for encointer we assume that every currency has its own shard. so shard == cid
                        None)
                        .sign(&sr25519_core::Pair::from(who), nonce, &mrenclave, &shard)
                        .into();
                    perform_operation(matches, &top);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("get-registration")
                .description("get participant registration index for next encointer ceremony")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let who = get_pair_from_str(matches, arg_who);
                    let (_mrenclave, shard) = get_identifiers(matches);
                    println!(
                        "send TrustedGetter::get_registration for {}",
                        who.public()
                    );
                    let top: TrustedOperation = TrustedGetter::registration(
                        sr25519_core::Public::from(who.public()),
                        shard, // for encointer we assume that every currency has its own shard. so shard == cid
                        )
                        .sign(&sr25519_core::Pair::from(who))
                        .into();
                    let part = perform_operation(matches, &top).unwrap();
                    let participant: ParticipantIndexType = Decode::decode(&mut part.as_slice()).unwrap();
                    println!("Participant index: {:?}", participant);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("register-attestations")
                .description("register encointer ceremony attestations")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                        .arg(
                            Arg::with_name("attestations")
                                .takes_value(true)
                                .required(true)
                                .multiple(true)
                                .min_values(2)
                        )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let who = get_pair_from_str(matches, arg_who);
                    let (mrenclave, shard) = get_identifiers(matches);
                    let nonce = 0; // FIXME: hard coded for now
                    let attestation_args: Vec<_> = matches.values_of("attestations").unwrap().collect();
                    let mut attestations: Vec<Attestation<MultiSignature, AccountId32, Moment>> = vec![];
                    for arg in attestation_args.iter() {
                        let w = Attestation::decode(&mut &hex::decode(arg).unwrap()[..]).unwrap();
                        attestations.push(w);
                    }
                    println!(
                        "send TrustedCall::register_attestations for {}",
                        who.public()
                    );
                    let top: TrustedOperation = TrustedCall::ceremonies_register_attestations(
                        sr25519_core::Public::from(who.public()),
                        attestations
                        )
                        .sign(&sr25519_core::Pair::from(who), nonce, &mrenclave, &shard)
                        .into();
                    perform_operation(matches, &top);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("get-attestations")
                .description("get attestations registration index for this encointer ceremony")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    let who = get_pair_from_str(matches, arg_who);
                    let (_mrenclave, shard) = get_identifiers(matches);
                    println!(
                        "send TrustedGetter::get_attestations for {}",
                        who.public(),
                    );
                    let top: TrustedOperation = TrustedGetter::attestations(
                        sr25519_core::Public::from(who.public()),
                        shard, // for encointer we assume that every currency has its own shard. so shard == cid
                        )
                        .sign(&sr25519_core::Pair::from(who))
                        .into();
                    let attestations = perform_operation(matches, &top).unwrap();
                    println!("Attestations: {:?}", hex::encode(attestations));
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("new-claim")
                .description("read current ceremony phase from chain")
                .options(|app| {
                    app.arg(
                        Arg::with_name("accountid")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("AccountId in ss58check format"),
                    )
                        .arg(
                            Arg::with_name("n-participants")
                                .takes_value(true)
                                .required(true)
                        )
                })
                .runner(move |_args: &str, matches: &ArgMatches<'_>| {
                    let arg_who = matches.value_of("accountid").unwrap();
                    // println!("arg_who = {:?}", arg_who);
                    let who = get_pair_from_str(matches, arg_who);

                    let n_participants = matches
                        .value_of("n-participants")
                        .unwrap()
                        .parse::<u32>()
                        .unwrap();

                    let (_mrenclave, shard) = get_identifiers(matches);
                    let top: TrustedOperation = TrustedGetter::meetup_index_time_and_location(who.public().into(), shard)
                        .sign(&sr25519_core::Pair::from(who.clone()))
                        .into();

                    let res = perform_operation(matches, &top).unwrap();
                    let (mindex, mlocation, mtime): (MeetupIndexType, Option<Location>, Option<Moment>) = Decode::decode(&mut res.as_slice()).unwrap();
                    info!("got mindex: {:?}", mindex);
                    info!("got time: {:?}", mtime);
                    info!("got location: {:?}", mlocation);
                    let api = get_chain_api(matches);
                    let cindex = api.get_storage_value("EncointerScheduler", "CurrentCeremonyIndex", None)
                        .unwrap();

                    let claim = ClaimOfAttendance::<AccountId, Moment> {
                        claimant_public: who.public().into(),
                        currency_identifier: shard,
                        ceremony_index: cindex,
                        // ceremony_index: Default::default(),
                        meetup_index: mindex,
                        location: mlocation.unwrap(),
                        timestamp: mtime.unwrap(),
                        number_of_participants_confirmed: n_participants,
                    };
                    println!("{}", hex::encode(claim.encode()));
                    Ok(())
                }),
        )
        .into_cmd("trusted")
}

fn get_keystore_path(matches: &ArgMatches<'_>) -> PathBuf {
    let (_mrenclave, shard) = get_identifiers(matches);
    PathBuf::from(&format!("{}/{}", KEYSTORE_PATH, shard.encode().to_base58()))
}

pub fn get_identifiers(matches: &ArgMatches<'_>) -> ([u8; 32], ShardIdentifier) {
    let mut mrenclave = [0u8; 32];
    if !matches.is_present("mrenclave") {
        panic!("--mrenclave must be provided");
    };
    mrenclave.copy_from_slice(
        &matches
            .value_of("mrenclave")
            .unwrap()
            .from_base58()
            .expect("mrenclave has to be base58 encoded"),
    );
    let shard = match matches.value_of("shard") {
        Some(val) => ShardIdentifier::from_slice(
            &val.from_base58()
                .expect("mrenclave has to be base58 encoded"),
        ),
        None => ShardIdentifier::from_slice(&mrenclave),
    };
    (mrenclave, shard)
}
// TODO this function is redundant with client::main
fn get_accountid_from_str(account: &str) -> AccountId {
    match &account[..2] {
        "//" => sr25519::Pair::from_string(account, None)
            .unwrap()
            .public()
            .into_account(),
        _ => sr25519::Public::from_ss58check(account)
            .unwrap()
            .into_account(),
    }
}

// TODO this function is redundant with client::main
// get a pair either form keyring (well known keys) or from the store
fn get_pair_from_str(matches: &ArgMatches<'_>, account: &str) -> sr25519::AppPair {
    info!("getting pair for {}", account);
    match &account[..2] {
        "//" => sr25519::AppPair::from_string(account, None).unwrap(),
        _ => {
            info!("fetching from keystore at {}", &KEYSTORE_PATH);
            // open store without password protection
            let store = Store::open(get_keystore_path(matches), None).expect("store should exist");
            info!("store opened");
            let _pair = store
                .read()
                .key_pair::<sr25519::AppPair>(
                    &sr25519::Public::from_ss58check(account).unwrap().into(),
                )
                .unwrap();
            info!("key pair fetched");
            drop(store);
            _pair
        }
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

fn get_block_number(api: &Api<sr25519::Pair>) -> BlockNumber {
    let hdr: Header = api.get_header(None).unwrap();
    debug!("decoded: {:?}", hdr);
    //let hdr: Header= Decode::decode(&mut .as_bytes()).unwrap();
    hdr.number
}

fn get_demurrage_per_block(api: &Api<sr25519::Pair>, cid: CurrencyIdentifier) -> BalanceType {
    let cp: CurrencyPropertiesType = api
        .get_storage_map("EncointerCurrencies", "CurrencyProperties", cid, None)
        .unwrap();
    debug!("CurrencyProperties are {:?}", cp);
    cp.demurrage_per_block
}

fn apply_demurrage(entry: BalanceEntry<BlockNumber>, current_block: BlockNumber, demurrage_per_block: BalanceType) -> BalanceType {
    let elapsed_time_block_number = current_block.checked_sub(entry.last_update).unwrap();
    let elapsed_time_u32: u32 = elapsed_time_block_number.into();
    let elapsed_time = BalanceType::from_num(elapsed_time_u32);
    let exponent : BalanceType = -demurrage_per_block * elapsed_time;
    debug!("demurrage per block {}, current_block {}, last {}, elapsed_blocks {}", demurrage_per_block, current_block, entry.last_update, elapsed_time);
    let exp_result : BalanceType = exp(exponent).unwrap();
    entry.principal.checked_mul(exp_result).unwrap()
}

