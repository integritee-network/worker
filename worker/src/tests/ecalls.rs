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

use crate::enclave::api::{enclave_execute_stf, enclave_query_state};
use crate::init_shard;
use crate::tests::commons::{encrypted_test_msg, test_trusted_getter_signed};
use base58::ToBase58;
use codec::Encode;
use keyring::AccountKeyring;
use std::fs;

use primitives::hash::H256;
use sgx_types::*;

// TODO: test get_ecc_signing_pubkey
// TODO: test get_rsa_encryption_pubkey

pub fn get_state_works(eid: sgx_enclave_id_t) {
    let alice = AccountKeyring::Alice;
    let trusted_getter_signed = test_trusted_getter_signed(alice).encode();
    let shard = H256::default();
    init_shard(&shard);
    let res = enclave_query_state(eid, trusted_getter_signed, shard.encode()).unwrap();
    println!("get_state returned {:?}", res);
}

pub fn execute_stf_works(eid: sgx_enclave_id_t) {
    let cyphertext = encrypted_test_msg(eid);
    let nonce = 0u32;
    let genesis_hash: [u8; 32] = [0; 32];
    let shard = H256::default();

    // create the state such that we do not need to initialize it manually
    let path = "./shards/".to_owned() + &shard.encode().to_base58();
    fs::create_dir_all(&path).unwrap();
    fs::File::create(path + "/state.bin").unwrap();

    let node_url = format!("ws://{}:{}", "127.0.0.1", "9944");

    let _uxt = enclave_execute_stf(
        eid,
        cyphertext,
        shard.encode(),
        genesis_hash.encode(),
        nonce,
        node_url,
    )
    .unwrap();
}
