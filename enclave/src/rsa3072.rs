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

use std::sgxfs::SgxFile;
use std::vec::Vec;

use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use sgx_crypto_helper::RsaKeyPair;
use sgx_types::*;

use log::*;

use crate::constants::RSA3072_SEALED_KEY_FILE;
use crate::io;

pub fn unseal_pair() -> SgxResult<Rsa3072KeyPair> {
    let keyvec = io::unseal(RSA3072_SEALED_KEY_FILE)?;
    let key_json_str = std::str::from_utf8(&keyvec).unwrap();
    let pair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
    Ok(pair)
}

pub fn unseal_pubkey() -> SgxResult<Rsa3072PubKey> {
    let pair = (unseal_pair())?;
    let pubkey = pair.export_pubkey().unwrap();

    Ok(pubkey)
}

pub fn create_sealed_if_absent() -> SgxResult<sgx_status_t> {
    if SgxFile::open(RSA3072_SEALED_KEY_FILE).is_err() {
        info!(
            "[Enclave] Keyfile not found, creating new! {}",
            RSA3072_SEALED_KEY_FILE
        );
        return create_sealed();
    }
    Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn create_sealed() -> Result<sgx_status_t, sgx_status_t> {
    let rsa_keypair = Rsa3072KeyPair::new().unwrap();
    let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
    // println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
    seal(rsa_key_json.as_bytes())
}

pub fn seal(pair: &[u8]) -> SgxResult<sgx_status_t> {
    io::seal(pair, RSA3072_SEALED_KEY_FILE)
}

pub fn decrypt(ciphertext_slice: &[u8], rsa_pair: &Rsa3072KeyPair) -> SgxResult<Vec<u8>> {
    let mut decrypted_buffer = Vec::new();

    rsa_pair.decrypt_buffer(ciphertext_slice, &mut decrypted_buffer)?;
    Ok(decrypted_buffer)
}
