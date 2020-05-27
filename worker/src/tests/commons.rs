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
use codec::Encode;
use log::*;
use serde_derive::{Deserialize, Serialize};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sp_core::crypto::AccountId32;
use sp_core::sr25519;
use sp_keyring::AccountKeyring;

use std::{fs, str};

use crate::enclave::api::*;
use crate::{enclave_account, enclave_mrenclave, ensure_account_has_funds};
use substrate_api_client::Api;
use substratee_stf::{ShardIdentifier, TrustedCall, TrustedGetter, TrustedGetterSigned};

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub account: String,
    pub amount: u32,
    pub sha256: sgx_sha256_hash_t,
}

/// Who must be root account
pub fn encrypted_set_balance(eid: sgx_enclave_id_t, who: AccountKeyring, nonce: u32) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let rsa_pubkey: Rsa3072PubKey = enclave_shielding_key(eid).unwrap();
    info!("deserialized rsa key");

    let call = TrustedCall::balance_set_balance(who.public(), who.public(), 33, 44);
    encrypt_payload(
        rsa_pubkey,
        call.sign(
            &who.pair(),
            nonce,
            &enclave_mrenclave(eid).unwrap(),
            &ShardIdentifier::default(),
        )
        .encode(),
    )
}

pub fn encrypted_unshield(eid: sgx_enclave_id_t, who: AccountKeyring, nonce: u32) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let rsa_pubkey: Rsa3072PubKey = enclave_shielding_key(eid).unwrap();
    info!("deserialized rsa key");

    let call =
        TrustedCall::balance_unshield(who.public(), who.public(), 40, ShardIdentifier::default());
    encrypt_payload(
        rsa_pubkey,
        call.sign(
            &who.pair(),
            nonce,
            &enclave_mrenclave(eid).unwrap(),
            &ShardIdentifier::default(),
        )
        .encode(),
    )
}

pub fn encrypt_payload(rsa_pubkey: Rsa3072PubKey, payload: Vec<u8>) -> Vec<u8> {
    let mut payload_encrypted: Vec<u8> = Vec::new();
    rsa_pubkey
        .encrypt_buffer(&payload, &mut payload_encrypted)
        .unwrap();
    payload_encrypted
}

pub fn test_trusted_getter_signed(who: AccountKeyring) -> TrustedGetterSigned {
    let getter = TrustedGetter::free_balance(who.public());
    getter.sign(&who.pair())
}

pub fn encrypted_alice(eid: sgx_enclave_id_t) -> Vec<u8> {
    info!("*** Get the public key from the TEE\n");
    let rsa_pubkey: Rsa3072PubKey = enclave_shielding_key(eid).unwrap();
    encrypt_payload(rsa_pubkey, AccountKeyring::Alice.encode())
}

pub fn setup(
    eid: sgx_enclave_id_t,
    who: Option<AccountKeyring>,
    port: &str,
) -> (Api<sr25519::Pair>, Option<u32>, ShardIdentifier) {
    let node_url = format!("ws://{}:{}", "127.0.0.1", port);
    let mut api = Api::<sr25519::Pair>::new(node_url);
    ensure_account_has_funds(&mut api, &enclave_account(eid));

    // create the state such that we do not need to initialize it manually
    let shard = ShardIdentifier::default();
    let path = "./shards/".to_owned() + &shard.encode().to_base58();
    fs::create_dir_all(&path).unwrap();
    fs::File::create(path + "/state.bin").unwrap();

    match who {
        Some(account) => {
            api = api.set_signer(account.pair());
            let nonce = get_nonce(&api, &account.to_account_id());
            (api, Some(nonce), shard)
        }
        None => (api, None, shard),
    }
}

pub fn get_nonce(api: &Api<sr25519::Pair>, who: &AccountId32) -> u32 {
    if let Some(info) = api.get_account_info(who) {
        info.nonce
    } else {
        0
    }
}
