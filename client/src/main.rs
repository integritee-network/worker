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

use sgx_types::*;

use clap::{load_yaml, App};
use codec::Encode;
use keyring::AccountKeyring;
use log::*;
use primitives::{crypto::Ss58Codec, Pair};
use runtime_primitives::{traits::Verify, AnySignature};
use serde_derive::{Deserialize, Serialize};
use substrate_api_client::{utils::hexstr_to_u256, Api};

use substratee_client::*;
use substratee_node_calls::{get_worker_amount, get_worker_info};
use substratee_stf::{TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned};
use substratee_worker_api::Api as WorkerApi;

type AccountId = <AnySignature as Verify>::Signer;

fn main() {
    // message structure
    #[derive(Debug, Serialize, Deserialize)]
    struct Message {
        account: String,
        amount: u32,
        sha256: sgx_sha256_hash_t,
    }

    env_logger::init();

    let yml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yml).get_matches();

    let port = matches.value_of("node-ws-port").unwrap_or("9944");
    let server = matches.value_of("node-addr").unwrap_or("127.0.0.1");

    info!("initializing ws api to node");
    let alice = AccountKeyring::Alice.pair();
    info!(
        "use Alice account as signer = {}",
        alice.public().to_ss58check()
    );
    let api = Api::new(format!("ws://{}:{}", server, port)).set_signer(alice.clone());

    println!("*** Getting the amount of the registered workers");
    let worker = match get_worker_amount(&api) {
        0 => {
            println!("No worker in registry, returning...");
            return;
        }
        x => {
            println!("[<] Found {} workers\n", x);
            println!("[>] Getting the first worker's info from the substraTEE-node");
            get_worker_info(&api, 1)
        }
    };
    println!("[<] Got first worker's coordinates:");
    println!("    W1's public key : {:?}", worker.pubkey.to_string());
    println!(
        "    W1's url: {}\n",
        String::from_utf8_lossy(&worker.url[..]).to_string()
    );

    let worker_api = WorkerApi::new(String::from_utf8_lossy(&worker.url[..]).to_string());

    info!("getting free_balance for Alice");
    let result_str = api
        .get_storage(
            "Balances",
            "FreeBalance",
            Some(AccountId::from(alice.public()).encode()),
        )
        .unwrap();
    let funds = hexstr_to_u256(result_str).unwrap();
    info!("Alice free balance = {:?}", funds);
    info!("Alice's Account Nonce is {}", api.get_nonce().unwrap());

    // compose extrinsic with encrypted payload
    println!(
        "[>] Get the shielding key from W1 ({})",
        worker.pubkey.to_string()
    );
    let shielding_pubkey = worker_api.get_rsa_pubkey().unwrap();
    println!("[<] Got worker shielding key {:?}\n", shielding_pubkey);

    let alice_incognito_pair = pair_from_suri_sr("//AliceIncognito", Some(""));
    println!(
        "[+] Alice's Incognito Pubkey: {}\n",
        alice_incognito_pair.public()
    );

    let bob_incognito_pair = pair_from_suri_sr("//BobIncognito", Some(""));
    println!(
        "[+] Bob's Incognito Pubkey: {}\n",
        bob_incognito_pair.public()
    );

    println!("[+] pre-funding Alice's Incognito account (ROOT call)");
    let call = TrustedCall::balance_set_balance(alice_incognito_pair.public(), 1_000_000, 0);
    let call_signed = call.sign(
        &alice_incognito_pair,
        0,
        &worker.mr_enclave,
        &worker.mr_enclave);   // for demo we name the shard after our mrenclave

    call_trusted_stf(&api, call_signed, shielding_pubkey);

    println!("[+] query Alice's Incognito account balance");
    let getter = TrustedGetter::free_balance(alice_incognito_pair.public());
    let getter_signed =
        TrustedGetterSigned::new(getter.clone(), getter.sign(&alice_incognito_pair));
    get_trusted_stf_state(&worker_api, getter_signed);

    println!("[+] query Bob's Incognito account balance");
    let getter = TrustedGetter::free_balance(bob_incognito_pair.public());
    let getter_signed = TrustedGetterSigned::new(getter.clone(), getter.sign(&bob_incognito_pair));
    get_trusted_stf_state(&worker_api, getter_signed);

    println!("*** incognito transfer from Alice to Bob");
    let call = TrustedCall::balance_transfer(
        alice_incognito_pair.public(),
        bob_incognito_pair.public(),
        100_000,
    );
    let call_signed = call.sign(
        &alice_incognito_pair,
        0,
        &worker.mr_enclave,
        &worker.mr_enclave);   // for demo we name the shard after our mrenclave
    call_trusted_stf(&api, call_signed, shielding_pubkey);

    println!("[+] query Alice's Incognito account balance");
    let getter = TrustedGetter::free_balance(alice_incognito_pair.public());
    let getter_signed =
        TrustedGetterSigned::new(getter.clone(), getter.sign(&alice_incognito_pair));
    get_trusted_stf_state(&worker_api, getter_signed);

    println!("[+] query Bob's Incognito account balance");
    let getter = TrustedGetter::free_balance(bob_incognito_pair.public());
    let getter_signed = TrustedGetterSigned::new(getter.clone(), getter.sign(&bob_incognito_pair));
    get_trusted_stf_state(&worker_api, getter_signed);
}
