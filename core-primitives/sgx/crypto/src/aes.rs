/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use crate::{
	error::{Error, Result},
	traits::StateCrypto,
};
use aes::Aes128;
use codec::{Decode, Encode};
use derive_more::Display;
use itp_settings::files::AES_KEY_FILE_AND_INIT_V;
use itp_sgx_io::{seal, unseal, SealedIO};
use log::info;
use ofb::{
	cipher::{NewStreamCipher, SyncStreamCipher},
	Ofb,
};
use sgx_rand::{Rng, StdRng};
use std::{
	convert::{TryFrom, TryInto},
	sgxfs::SgxFile,
};

type AesOfb = Ofb<Aes128>;

#[derive(Debug, Default, Encode, Decode)]
pub struct Aes {
	pub key: [u8; 16],
	pub init_vec: [u8; 16],
}

impl Aes {
	pub fn new(key: [u8; 16], init_vec: [u8; 16]) -> Self {
		Self { key, init_vec }
	}
}

#[derive(Copy, Clone, Debug, Display)]
pub struct AesSeal;

impl SealedIO for AesSeal {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal() -> Result<Self::Unsealed> {
		Ok(unseal(AES_KEY_FILE_AND_INIT_V).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal(unsealed: Self::Unsealed) -> Result<()> {
		Ok(unsealed.using_encoded(|bytes| seal(bytes, AES_KEY_FILE_AND_INIT_V))?)
	}
}

impl StateCrypto for Aes {
	type Error = Error;

	fn encrypt(data: &mut [u8]) -> Result<()> {
		AesSeal::unseal().map(|aes| de_or_encrypt(&aes, data))?
	}

	fn decrypt(data: &mut [u8]) -> Result<()> {
		AesSeal::unseal().map(|aes| de_or_encrypt(&aes, data))?
	}
}

impl TryFrom<&Aes> for AesOfb {
	type Error = Error;

	fn try_from(aes: &Aes) -> std::result::Result<Self, Self::Error> {
		Ok(AesOfb::new_var(&aes.key, &aes.init_vec).map_err(|_| Error::InvalidNonceKeyLength)?)
	}
}

pub fn create_sealed_if_absent() -> Result<()> {
	if SgxFile::open(AES_KEY_FILE_AND_INIT_V).is_err() {
		info!("[Enclave] Keyfile not found, creating new! {}", AES_KEY_FILE_AND_INIT_V);
		return create_sealed()
	}
	Ok(())
}

pub fn create_sealed() -> Result<()> {
	let mut key = [0u8; 16];
	let mut iv = [0u8; 16];

	let mut rand = StdRng::new()?;

	rand.fill_bytes(&mut key);
	rand.fill_bytes(&mut iv);
	AesSeal::seal(Aes::new(key, iv))
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn de_or_encrypt(aes: &Aes, data: &mut [u8]) -> Result<()> {
	Ok(aes.try_into().map(|mut ofb: AesOfb| ofb.apply_keystream(data))?)
}
