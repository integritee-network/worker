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

use clap::{Arg, ArgMatches, SubCommand};
use clap_nested::{Commander, Command, MultiCommand};
use crate::{AccountId, TrustedCall, TrustedCallSigned, TrustedOperationSigned, ShardIdentifier};
use log::*;
use base58::FromBase58;
use application_crypto::{ed25519, sr25519};
use primitives::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use runtime_primitives::traits::IdentifyAccount;
use keystore::Store;
use std::path::PathBuf;

const KEYSTORE_PATH: &str = "my_trusted_keystore";
const PREFUNDING_AMOUNT: u128 = 1_000_000_000;

pub fn cmd<'a>(perform_operation: &'a Fn(&ArgMatches<'_>, &TrustedOperationSigned)) -> MultiCommand<'a, str, str> {
    Commander::new()
        .options(|app| {
            app.arg(
                Arg::with_name("worker-url")
                    .short("wu")
                    .long("worker-url")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("127.0.0.1")
                    .help("worker url"),
            )
            .arg(
                Arg::with_name("worker-port")
                    .short("wp")
                    .long("worker-port")
                    .global(true)
                    .takes_value(true)
                    .value_name("STRING")
                    .default_value("2000")
                    .help("worker port"),
            )
            .arg(
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
                    let from = get_pair_from_str(arg_from);
                    let to = get_accountid_from_str(arg_to);
                    info!("from ss58 is {}", from.public().to_ss58check());
                    info!("to ss58 is {}", to.to_ss58check());

                    let mut mrenclave = [ 0u8; 32 ];
                    if !matches.is_present("mrenclave") {
                        panic!("--mrenclave must be provided");
                    };
                    mrenclave.copy_from_slice(&matches.value_of("mrenclave").unwrap().from_base58()
                        .expect("mrenclave has to be base58 encoded"));
                    let shard = match matches.value_of("shard") {
                        Some(val) => ShardIdentifier::from_slice(&val.from_base58()
                            .expect("mrenclave has to be base58 encoded")),
                        None => ShardIdentifier::from_slice(&mrenclave),
                    };
                    let tcall = TrustedCall::balance_transfer(
                        sr25519_core::Public::from(from.public()) ,
                        sr25519_core::Public::from(to),
                        amount,
                    );
                    let nonce = 0; // FIXME: hard coded for now
                    let tscall = tcall.sign(&sr25519_core::Pair::from(from), 
                        nonce, &mrenclave, &shard);
                    println!("call from: {}", tscall.call.account());
                    perform_operation(matches, &TrustedOperationSigned::call(tscall));
                    Ok(())
                })
        )
        .into_cmd("trusted")
    }


// TODO this function is redundant with client::main
fn get_accountid_from_str(account: &str) -> AccountId {
    match &account[..2] {
        "//" => AccountId::from(sr25519::Pair::from_string(account, None).unwrap().public())
            .into_account(),
        _ => AccountId::from(sr25519::Public::from_ss58check(account).unwrap()).into_account(),
    }
}

// TODO this function is redundant with client::main
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