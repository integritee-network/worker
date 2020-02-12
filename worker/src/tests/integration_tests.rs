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
use primitives::{crypto::AccountId32, ed25519, hash::H256};
use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::fs;
use substrate_api_client::{extrinsic::xt_primitives::GenericAddress, utils::hexstr_to_u256, Api};

use my_node_runtime::substratee_registry::Request;

use crate::constants::*;
use crate::enclave::api::*;
use crate::tests::commons::*;

pub fn perform_ra_works(eid: sgx_enclave_id_t, port: &str) {
    // start the substrate-api-client to communicate with the node
    let api = Api::<ed25519::Pair>::new(format!("ws://127.0.0.1:{}", port));

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
    let nonce_bytes = nonce.encode();
    debug!("Enclave nonce = {:?}", nonce);
    let xt =
        enclave_perform_ra(eid, genesis_hash, nonce_bytes.encode(), w_url.encode()).unwrap();
}

pub fn process_forwarded_payload_works(eid: sgx_enclave_id_t, port: &str) {
    let req = Request {
        cyphertext: encrypted_test_msg(eid.clone()),
        shard: H256::default(),
    };
    crate::process_request(eid, req, port);
}
