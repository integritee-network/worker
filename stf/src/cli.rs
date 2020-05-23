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

use crate::{AccountId, ShardIdentifier, TrustedCall, TrustedGetter, TrustedOperationSigned};
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

const KEYSTORE_PATH: &str = "my_trusted_keystore";

pub fn cmd<'a>(
    perform_operation: &'a dyn Fn(&ArgMatches<'_>, &TrustedOperationSigned) -> Option<Vec<u8>>,
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

                    let (mrenclave, shard) = get_identifiers(matches);

                    let tcall = TrustedCall::balance_transfer(
                        sr25519_core::Public::from(from.public()),
                        to,
                        amount,
                    );
                    let nonce = 0; // FIXME: hard coded for now
                    let tscall =
                        tcall.sign(&sr25519_core::Pair::from(from), nonce, &mrenclave, &shard);
                    println!(
                        "send trusted call transfer from {} to {}: {}",
                        tscall.call.account(),
                        to,
                        amount
                    );
                    let _ = perform_operation(matches, &TrustedOperationSigned::call(tscall));
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("set-balance")
                .description("ROOT call to set some account balance to an arbitrary number")
                .options(|app| {
                    app.arg(
                        Arg::with_name("account")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("sender's AccountId in ss58check format"),
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
                    let arg_who = matches.value_of("account").unwrap();
                    let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                        .expect("amount can be converted to u128");
                    let who = get_pair_from_str(matches, arg_who);
                    let signer = get_pair_from_str(matches, "//AliceIncognito");
                    info!("account ss58 is {}", who.public().to_ss58check());

                    let (mrenclave, shard) = get_identifiers(matches);

                    let tcall = TrustedCall::balance_set_balance(
                        sr25519_core::Public::from(signer.public()),
                        sr25519_core::Public::from(who.public()),
                        amount,
                        amount,
                    );
                    let nonce = 0; // FIXME: hard coded for now
                    let tscall =
                        tcall.sign(&sr25519_core::Pair::from(signer), nonce, &mrenclave, &shard);
                    println!(
                        "send trusted call set-balance({}, {})",
                        tscall.call.account(),
                        amount
                    );
                    let _ = perform_operation(matches, &TrustedOperationSigned::call(tscall));
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
                    let tgetter =
                        TrustedGetter::free_balance(sr25519_core::Public::from(who.public()));
                    let tsgetter = tgetter.sign(&sr25519_core::Pair::from(who));
                    let res = perform_operation(matches, &TrustedOperationSigned::get(tsgetter));
                    let bal = if let Some(v) = res {
                        if let Ok(vd) = crate::Balance::decode(&mut v.as_slice()) {
                            vd
                        } else {
                            info!("could not decode value. maybe hasn't been set? {:x?}", v);
                            0
                        }
                    } else {
                        0
                    };
                    println!("{}", bal);
                    Ok(())
                }),
        )
        .add_cmd(
            Command::new("unshield-funds")
                .description("Transfer funds from an incognito account to an on-chain account")
                .options(|app| {
                    app.arg(
                        Arg::with_name("from")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("Sender's incognito AccountId in ss58check format"),
                    )
                    .arg(
                        Arg::with_name("to")
                            .takes_value(true)
                            .required(true)
                            .value_name("SS58")
                            .help("Recipient's on-chain AccountId in ss58check format"),
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
                    let arg_from = matches.value_of("from").unwrap();
                    let arg_to = matches.value_of("to").unwrap();
                    let amount = u128::from_str_radix(matches.value_of("amount").unwrap(), 10)
                        .expect("amount can be converted to u128");
                    let from = get_pair_from_str(matches, arg_from);
                    let to = get_accountid_from_str(arg_to);
                    println!("from ss58 is {}", from.public().to_ss58check());
                    println!("to   ss58 is {}", to.to_ss58check());

                    let (mrenclave, shard) = get_identifiers(matches);

                    println!(
                        "send trusted call unshield_funds from {} to {}: {}",
                        from.public(),
                        to,
                        amount
                    );

                    let tcall = TrustedCall::balance_unshield(
                        sr25519_core::Public::from(from.public()),
                        to,
                        amount,
                        shard,
                    );
                    let nonce = 0; // FIXME: hard coded for now
                    let tscall =
                        tcall.sign(&sr25519_core::Pair::from(from), nonce, &mrenclave, &shard);
                    perform_operation(matches, &TrustedOperationSigned::call(tscall));
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

/*
pub fn call_trusted_stf<P: Pair>(
    api: &Api<P>,
    call: TrustedCallSigned,
    rsa_pubkey: Rsa3072PubKey,
    shard: &ShardIdentifier,
) where
    MultiSignature: From<P::Signature>,
{
    let call_encoded = call.encode();
    let mut call_encrypted: Vec<u8> = Vec::new();
    rsa_pubkey
        .encrypt_buffer(&call_encoded, &mut call_encrypted)
        .unwrap();
    let request = Request {
        shard: shard.clone(),
        cyphertext: call_encrypted.clone(),
    };

    let xt = compose_extrinsic!(api.clone(), "SubstraTEERegistry", "call_worker", request);

    // send and watch extrinsic until finalized
    let tx_hash = api.send_extrinsic(xt.hex_encode()).unwrap();
    info!("stf call extrinsic got finalized. Hash: {:?}", tx_hash);
    info!("waiting for confirmation of stf call");
    let act_hash = subscribe_to_call_confirmed(api.clone());
    info!("callConfirmed event received");
    debug!(
        "Expected stf call Hash: {:?}",
        blake2s(32, &[0; 32], &call_encrypted).as_bytes()
    );
    debug!("confirmation stf call Hash:   {:?}", act_hash);
}

pub fn get_trusted_stf_state(
    workerapi: &WorkerApi,
    getter: TrustedGetterSigned,
    shard: &ShardIdentifier,
) {
    //TODO: #91
    //  encrypt getter
    //  decrypt response and verify signature
    debug!("calling workerapi to get value");
    let ret = workerapi
        .get_stf_state(getter, shard)
        .expect("getting value failed");
    let ret_cropped = &ret[..9 * 2];
    debug!(
        "got getter response from worker: {:?}\ncropping to {:?}",
        ret, ret_cropped
    );
    let valopt: Option<Vec<u8>> = Decode::decode(&mut &ret_cropped[..]).unwrap();
    match valopt {
        Some(v) => {
            let value = U256::from_little_endian(&v);
            println!("    value = {}", value);
        }
        _ => error!("error getting value"),
    };
}
*/
