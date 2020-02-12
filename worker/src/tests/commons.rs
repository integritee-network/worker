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
use serde_derive::{Deserialize, Serialize};
use serde_json;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use std::str;
use substratee_stf;

use crate::enclave::api::*;
use substratee_stf::{TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned};

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub account: String,
    pub amount: u32,
    pub sha256: sgx_sha256_hash_t,
}

pub fn encrypted_test_msg(enclave: SgxEnclave) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let enclave = enclave_init().unwrap();
    let pubkey = enclave_shielding_key(enclave).unwrap();
    let rsa_pubkey: Rsa3072PubKey =
        serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();
    info!("deserialized rsa key");
    let payload = test_trusted_call_signed().encode();
    encrypt_payload(rsa_pubkey, payload)
}

pub fn encrypt_payload(rsa_pubkey: Rsa3072PubKey, payload: Vec<u8>) -> Vec<u8> {
    let mut payload_encrypted: Vec<u8> = Vec::new();
    rsa_pubkey
        .encrypt_buffer(&payload, &mut payload_encrypted)
        .unwrap();
    payload_encrypted
}

pub fn test_trusted_call_signed() -> TrustedCallSigned {
    let alice = AccountKeyring::Alice;
    let call = TrustedCall::balance_set_balance(alice.public(), 33, 44);
    let nonce = 21;
    let mrenclave = [0u8; 32];
    let shard = [1u8; 32];
    call.sign(&alice.pair(), nonce, &mrenclave, &shard)
}

pub fn test_trusted_getter_signed(who: AccountKeyring) -> TrustedGetterSigned {
    let getter = TrustedGetter::free_balance(who.public());
    TrustedGetterSigned::new(getter.clone(), getter.sign(&who.pair()))
}

pub fn evaluate_result(result: sgx_status_t) {
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            error!("[<] Error processing in enclave enclave");
            panic!("");
        }
    }
}
