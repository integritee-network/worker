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

use codec::{Decode, Encode};
use log::*;
use sgx_types::*;
use sp_core::{crypto::AccountId32, sr25519};
use sp_keyring::AccountKeyring;
use std::fs;
use substrate_api_client::{Api, XtStatus};

use substratee_node_runtime::substratee_registry::Request;

use crate::constants::*;
use crate::enclave::api::*;
use crate::enclave_account;
use crate::tests::commons::*;
use substrate_api_client::extrinsic::xt_primitives::UncheckedExtrinsicV4;
use substratee_node_calls::ShardIdentifier;
use substratee_node_runtime::Header;
use substratee_stf::BalanceTransferFn;

type SubstrateeConfirmCallFn = ([u8; 2], ShardIdentifier, Vec<u8>, Vec<u8>);

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

pub fn process_forwarded_payload_works(eid: sgx_enclave_id_t, port: &str) {
    let (_api, nonce, shard) = setup(eid, Some(AccountKeyring::Alice), port);
    let req = Request {
        cyphertext: encrypted_set_balance(eid, AccountKeyring::Alice, nonce.unwrap()),
        shard,
    };
    crate::process_request(eid, req, format!("ws://{}:{}", "127.0.0.1", port).as_str());
}

pub fn execute_stf_set_balance_works(eid: sgx_enclave_id_t, port: &str) {
    let (api, nonce, shard) = setup(eid, Some(AccountKeyring::Alice), port);
    let cyphertext = encrypted_set_balance(eid, AccountKeyring::Alice, nonce.unwrap());
    execute_stf(eid, api, cyphertext, port, shard)
}

pub fn execute_stf_unshield_balance_works(eid: sgx_enclave_id_t, port: &str) {
    let (api, nonce, shard) = setup(eid, Some(AccountKeyring::Alice), port);
    let cyphertext = encrypted_unshield(eid, AccountKeyring::Alice, nonce.unwrap());
    execute_stf(eid, api, cyphertext, port, shard)
}

pub fn execute_stf(
    eid: sgx_enclave_id_t,
    api: Api<sr25519::Pair>,
    cyphertext: Vec<u8>,
    port: &str,
    shard: ShardIdentifier,
) {
    let node_url = format!("ws://{}:{}", "127.0.0.1", port);
    let tee_accountid = enclave_account(eid);
    info!("Executing STF");

    let nonce = get_nonce(&api, &tee_accountid);
    let genesis_hash = api.genesis_hash;

    let uxt = enclave_execute_stf(
        eid,
        cyphertext,
        shard.encode(),
        genesis_hash.encode(),
        nonce,
        node_url,
    )
    .unwrap();

    let mut extrinsics: Vec<Vec<u8>> = Decode::decode(&mut uxt.as_slice()).unwrap();
    info!("Enclave wants to send {} extrinsics", extrinsics.len());

    // send all unshield extrinsics
    while extrinsics.len() > 1 {
        let xt_vec = extrinsics.remove(0);

        let xt: UncheckedExtrinsicV4<BalanceTransferFn> =
            Decode::decode(&mut xt_vec.as_slice()).unwrap();
        info!("STF extrinsic: {:?}", xt);

        api.send_extrinsic(xt.hex_encode(), XtStatus::Finalized)
            .unwrap();
    }

    // the last element is always the confirmaton extrinsic
    let xt: UncheckedExtrinsicV4<SubstrateeConfirmCallFn> = extrinsics
        .pop()
        .map(|xt| Decode::decode(&mut xt.as_slice()).unwrap())
        .unwrap();

    info!("Call Confirm extrinsic: {:?}", xt);
    api.send_extrinsic(xt.hex_encode(), XtStatus::Finalized)
        .unwrap();
}

pub fn init_chain_relay(eid: sgx_enclave_id_t, port: &str) -> Header {
    let (api, _, _) = setup(eid, None, port);
    //
    crate::init_chain_relay(eid, &api)
}

pub fn sync_chain_relay(eid: sgx_enclave_id_t, port: &str, last_synced_head: Header) -> Header {
    let (api, _, _) = setup(eid, None, port);
    crate::sync_chain_relay(eid, &api, last_synced_head)
}
