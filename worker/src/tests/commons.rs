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
use keyring::AccountKeyring;
use log::*;
use primitives::sr25519;
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;

use std::str;
use substratee_stf;

use crate::enclave::api::*;
use crate::{ensure_account_has_funds, get_enclave_signing_key};
use substrate_api_client::utils::hexstr_to_u256;
use substrate_api_client::Api;
use substratee_stf::{
    ShardIdentifier, TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub account: String,
    pub amount: u32,
    pub sha256: sgx_sha256_hash_t,
}

pub fn encrypted_set_balance(eid: sgx_enclave_id_t, who: AccountKeyring, nonce: u32) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let rsa_pubkey: Rsa3072PubKey = enclave_shielding_key(eid)
        .map(|key| serde_json::from_slice(key.as_slice()).unwrap())
        .unwrap();
    info!("deserialized rsa key");

    let call = TrustedCall::balance_set_balance(who.public(), 33, 44);
    encrypt_payload(
        rsa_pubkey,
        test_trusted_call_signed(who, call, nonce).encode(),
    )
}

pub fn encrypted_unshield(eid: sgx_enclave_id_t, who: AccountKeyring, nonce: u32) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let rsa_pubkey: Rsa3072PubKey = enclave_shielding_key(eid)
        .map(|key| serde_json::from_slice(key.as_slice()).unwrap())
        .unwrap();
    info!("deserialized rsa key");

    let call = TrustedCall::balance_unshield(who.public(), 33);
    encrypt_payload(
        rsa_pubkey,
        test_trusted_call_signed(who, call, nonce).encode(),
    )
}

pub fn encrypt_payload(rsa_pubkey: Rsa3072PubKey, payload: Vec<u8>) -> Vec<u8> {
    let mut payload_encrypted: Vec<u8> = Vec::new();
    rsa_pubkey
        .encrypt_buffer(&payload, &mut payload_encrypted)
        .unwrap();
    payload_encrypted
}

pub fn test_trusted_call_signed(
    who: AccountKeyring,
    call: TrustedCall,
    nonce: u32,
) -> TrustedCallSigned {
    let mrenclave = [0u8; 32];
    let shard = ShardIdentifier::default();
    call.sign(&who.pair(), nonce, &mrenclave, &shard)
}

pub fn test_trusted_getter_signed(who: AccountKeyring) -> TrustedGetterSigned {
    let getter = TrustedGetter::free_balance(who.public());
    getter.sign(&who.pair())
}

pub fn setup(eid: sgx_enclave_id_t, who: AccountKeyring) -> (Api<sr25519::Pair>, u32) {
    let node_url = format!("ws://{}:{}", "127.0.0.1", "9944");
    let api = Api::<sr25519::Pair>::new(node_url.clone()).set_signer(who.pair());

    ensure_account_has_funds(&api, &get_enclave_signing_key(eid));

    let nonce = api
        .get_storage("System", "AccountNonce", Some(who.to_account_id().encode()))
        .map(|n| hexstr_to_u256(n).unwrap())
        .unwrap()
        .low_u32();
    (api, nonce)
}
