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

use codec::Encode;
use log::*;
use sgx_types::*;
use sp_core::crypto::{AccountId32, Pair};
use sp_keyring::AccountKeyring;
use std::fs;
use substrate_api_client::XtStatus;

use crate::constants::*;
use crate::enclave::api::*;
use crate::tests::commons::*;
use std::thread::sleep;
use std::time::Duration;
use substrate_api_client::{compose_extrinsic, extrinsic::xt_primitives::UncheckedExtrinsicV4};
use substratee_node_primitives::{CallWorkerFn, Request, ShieldFundsFn};
use substratee_node_runtime::Header;

pub fn perform_ra_works(eid: sgx_enclave_id_t, port: &str) {
    // start the substrate-api-client to communicate with the node
    let (api, _nonce, _shard) = setup(eid, Some(AccountKeyring::Alice), port);

    let w_url = "ws://127.0.0.1:2001";
    let genesis_hash = api.genesis_hash.as_bytes().to_vec();

    // get the public signing key of the TEE
    let mut key = [0; 32];
    let ecc_key = fs::read(SIGNING_KEY_FILE).expect("Unable to open ECC public key file");
    key.copy_from_slice(&ecc_key[..]);
    debug!("[+] Got ECC public key of TEE = {:?}", key);

    // get enclaves's account nonce
    let nonce = get_nonce(&api, &AccountId32::from(key));
    debug!("  TEE nonce is  {}", nonce);
    let _xt = enclave_perform_ra(eid, genesis_hash, nonce, w_url.encode()).unwrap();
}

pub fn call_worker_encrypted_set_balance_works(
    eid: sgx_enclave_id_t,
    port: &str,
    last_synced_head: Header,
) -> Header {
    let root = AccountKeyring::Alice; // Alice is configure as root in our STF
    let (api, nonce, shard) = setup(eid, Some(root), port);
    let req = Request {
        shard,
        cyphertext: encrypted_set_balance(eid, root, nonce.unwrap()),
    };

    let xt: UncheckedExtrinsicV4<CallWorkerFn> =
        compose_extrinsic!(api, "SubstrateeRegistry", "call_worker", req);

    api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();

    println!("Sleeping until block with shield funds is finalized...");
    sleep(Duration::new(10, 0));
    println!("Syncing Chain Relay to look for shield_funds extrinsic");
    crate::sync_chain_relay(eid, &api, last_synced_head)
}

pub fn forward_encrypted_unshield_works(
    eid: sgx_enclave_id_t,
    port: &str,
    last_synced_head: Header,
) -> Header {
    let (api, nonce, shard) = setup(eid, Some(AccountKeyring::Alice), port);
    let req = Request {
        cyphertext: encrypted_unshield(eid, AccountKeyring::Alice, nonce.unwrap()),
        shard,
    };

    let xt: UncheckedExtrinsicV4<CallWorkerFn> =
        compose_extrinsic!(api, "SubstrateeRegistry", "call_worker", req);

    api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();

    println!("Sleeping until block with shield funds is finalized...");
    sleep(Duration::new(10, 0));
    println!("Syncing Chain Relay to look for CallWorker with TrustedCall::unshield extrinsic");
    crate::sync_chain_relay(eid, &api, last_synced_head)
}

pub fn init_chain_relay(eid: sgx_enclave_id_t, port: &str) -> Header {
    let (api, _, _) = setup(eid, None, port);
    crate::init_chain_relay(eid, &api)
}

pub fn shield_funds_workds(eid: sgx_enclave_id_t, port: &str, last_synced_head: Header) -> Header {
    let (api, _nonce, shard) = setup(eid, Some(AccountKeyring::Alice), port);

    let xt: UncheckedExtrinsicV4<ShieldFundsFn> = compose_extrinsic!(
        api,
        "SubstrateeRegistry",
        "shield_funds",
        encrypted_alice(eid),
        444u128,
        shard
    );
    let tx_hash = api
        .send_extrinsic(xt.hex_encode(), XtStatus::InBlock)
        .unwrap();
    println!("[+] Transaction got finalized. Hash: {:?}\n", tx_hash);

    println!("Sleeping until block with shield funds is finalized...");
    sleep(Duration::new(10, 0));
    println!("Syncing Chain Relay to look for shield_funds extrinsic");
    crate::sync_chain_relay(eid, &api, last_synced_head)
}
