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

use base58::ToBase58;
use codec::{Decode, Encode};
use keyring::AccountKeyring;
use log::*;
use primitives::{crypto::AccountId32, hash::H256, sr25519};
use sgx_types::*;
use std::fs;
use substrate_api_client::{extrinsic::xt_primitives::GenericAddress, utils::hexstr_to_u256, Api};

use my_node_runtime::substratee_registry::Request;

use crate::constants::*;
use crate::enclave::api::*;
use crate::tests::commons::*;
use crate::{ensure_account_has_funds, get_enclave_signing_key};

pub fn perform_ra_works(eid: sgx_enclave_id_t, port: &str) {
    // start the substrate-api-client to communicate with the node
    let api = Api::<sr25519::Pair>::new(format!("ws://127.0.0.1:{}", port));

    let w_url = "ws://127.0.0.1:2001";
    let genesis_hash = api.genesis_hash.as_bytes().to_vec();

    // get the public signing key of the TEE
    let mut key = [0; 32];
    let ecc_key = fs::read(SIGNING_KEY_FILE).expect("Unable to open ECC public key file");
    key.copy_from_slice(&ecc_key[..]);
    debug!("[+] Got ECC public key of TEE = {:?}", key);

    // get enclaves's account nonce
    let result_str = api
        .get_storage(
            "System",
            "AccountNonce",
            Some(GenericAddress::from(AccountId32::from(key)).encode()),
        )
        .unwrap();
    let nonce = hexstr_to_u256(result_str).unwrap().low_u32();
    debug!("  TEE nonce is  {}", nonce);
    let _xt = enclave_perform_ra(eid, genesis_hash, nonce, w_url.encode()).unwrap();
}

pub fn process_forwarded_payload_works(eid: sgx_enclave_id_t, port: &str) {
    let (_api, nonce) = setup(eid, AccountKeyring::Alice);
    let req = Request {
        cyphertext: encrypted_set_balance(eid, AccountKeyring::Alice, nonce),
        shard: H256::default(),
    };
    crate::process_request(eid, req, port);
}

pub fn execute_stf_set_balance_works(eid: sgx_enclave_id_t) {
    let (api, nonce) = setup(eid, AccountKeyring::Alice);
    let cyphertext = encrypted_set_balance(eid, AccountKeyring::Alice, nonce.clone());
    execute_stf(eid, api, cyphertext)
}

pub fn execute_stf_unshield_balance_works(eid: sgx_enclave_id_t) {
    let (api, nonce) = setup(eid, AccountKeyring::Alice);
    let cyphertext = encrypted_unshield(eid, AccountKeyring::Alice, nonce.clone());
    execute_stf(eid, api, cyphertext)
}

pub fn execute_stf(eid: sgx_enclave_id_t, api: Api<sr25519::Pair>, cyphertext: Vec<u8>) {
    let node_url = format!("ws://{}:{}", "127.0.0.1", "9944");
    let tee_account_id = get_enclave_signing_key(eid);

    let nonce = hexstr_to_u256(
        api.get_storage("System", "AccountNonce", Some(tee_account_id.encode()))
            .unwrap(),
    )
    .unwrap()
    .low_u32();

    let genesis_hash = api.genesis_hash;
    let shard = H256::default();

    // create the state such that we do not need to initialize it manually
    let path = "./shards/".to_owned() + &shard.encode().to_base58();
    fs::create_dir_all(&path).unwrap();
    fs::File::create(path + "/state.bin").unwrap();

    let uxt = enclave_execute_stf(
        eid,
        cyphertext,
        shard.encode(),
        genesis_hash.encode(),
        nonce,
        node_url,
    )
    .unwrap();

    let extrinsics: Vec<Vec<u8>> = Decode::decode(&mut uxt.as_slice()).unwrap();

    extrinsics.iter().for_each(|xt| {
        let mut xt = hex::encode(xt);
        xt.insert_str(0, "0x");
        api.send_extrinsic(xt).unwrap();
    });
}
