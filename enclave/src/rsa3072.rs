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

use std::{sgxfs::SgxFile, vec::Vec};

use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use sgx_types::*;

use derive_more::{Display, From};
use log::*;

use crate::io;
use substratee_settings::files::RSA3072_SEALED_KEY_FILE;

pub fn unseal_pair() -> Result<Rsa3072KeyPair> {
	let keyvec = io::unseal(RSA3072_SEALED_KEY_FILE).map_err(|_| Error::Unseal)?;
	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
	let pair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
	Ok(pair)
}

pub fn unseal_pubkey() -> Result<Rsa3072PubKey> {
	let pair = unseal_pair()?;
	let pubkey = pair.export_pubkey().unwrap();

	Ok(pubkey)
}

pub fn create_sealed_if_absent() -> Result<()> {
	if SgxFile::open(RSA3072_SEALED_KEY_FILE).is_err() {
		info!("[Enclave] Keyfile not found, creating new! {}", RSA3072_SEALED_KEY_FILE);
		return create_sealed()
	}
	Ok(())
}

pub fn create_sealed() -> Result<()> {
	let rsa_keypair = Rsa3072KeyPair::new().unwrap();
	let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
	// println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
	seal(rsa_key_json.as_bytes())
}

pub fn seal(pair: &[u8]) -> Result<()> {
	io::seal(pair, RSA3072_SEALED_KEY_FILE).map_err(|_| Error::Seal)?;
	Ok(())
}

pub fn decrypt(ciphertext_slice: &[u8], rsa_pair: &Rsa3072KeyPair) -> Result<Vec<u8>> {
	let mut decrypted_buffer = Vec::new();

	rsa_pair.decrypt_buffer(ciphertext_slice, &mut decrypted_buffer)?;
	Ok(decrypted_buffer)
}

use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, Display, From)]
pub enum Error {
	Unseal,
	Seal,
	Decrypt(sgx_status_t),
}

impl<T> From<Error> for StdResult<T, Error> {
	fn from(error: Error) -> StdResult<T, Error> {
		Err(error)
	}
}

impl From<Error> for sgx_status_t {
	/// return sgx_status for top level enclave functions
	fn from(error: Error) -> sgx_status_t {
		match error {
			Error::Decrypt(status) => status,
			_ => {
				log::error!("RsaError into sgx_status: {:?}", error);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		}
	}
}
