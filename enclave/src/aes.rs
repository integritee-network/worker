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

use crate::error::{Error, Result};
use aes::Aes128;
use log::{info, trace};
use ofb::{
	cipher::{NewStreamCipher, SyncStreamCipher},
	Ofb,
};
use sgx_rand::{Rng, StdRng};
use sgx_types::*;
use std::{sgxfs::SgxFile, vec::Vec};
use substratee_sgx_io::{seal, unseal, SealIO};

use crate::utils::UnwrapOrSgxErrorUnexpected;
use substratee_settings::files::AES_KEY_FILE_AND_INIT_V;

type AesOfb = Ofb<Aes128>;

#[derive(Debug, Default, Encode, Decode)]
pub struct Aes {
	pub(crate) key: [u8; 16],
	pub(crate) init_vec: [u8; 16],
}

impl Aes {
	pub fn new(key: [u8; 16], init_vec: [u8; 16]) -> Self {
		Self { key, init_vec }
	}
}

impl SealIO for Aes {
	type Error = Error;
	fn unseal() -> Result<Self> {
		Ok(unseal(AES_KEY_FILE_AND_INIT_V).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal(self) -> Result<()> {
		Ok(self.using_encoded(|bytes| seal(bytes, AES_KEY_FILE_AND_INIT_V))?)
	}
}

pub fn create_sealed_if_absent() -> SgxResult<sgx_status_t> {
	if SgxFile::open(AES_KEY_FILE_AND_INIT_V).is_err() {
		info!("[Enclave] Keyfile not found, creating new! {}", AES_KEY_FILE_AND_INIT_V);
		create_sealed()?;
	}
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn create_sealed() -> Result<()> {
	let mut key = [0u8; 16];
	let mut iv = [0u8; 16];

	let mut rand = StdRng::new()?;

	rand.fill_bytes(&mut key);
	rand.fill_bytes(&mut iv);
	Aes::new(key, iv).seal()
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn de_or_encrypt(bytes: &mut Vec<u8>) -> Result<()> {
	Ok(Aes::unseal()
		.map(|aes| AesOfb::new_var(&aes.key, &aes.init_vec))
		.sgx_error_with_log("    [Enclave]  Failed to Initialize AES")?
		.map(|mut ofb| ofb.apply_keystream(bytes))
		.sgx_error_with_log("    [Enclave] Failed to AES en-/decrypt")?)
}
