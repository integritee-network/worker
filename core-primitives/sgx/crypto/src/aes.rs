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
use ofb::{
	cipher::{NewStreamCipher, SyncStreamCipher},
	Ofb,
};
use std::convert::{TryFrom, TryInto};

type AesOfb = Ofb<Aes128>;

#[derive(Debug, Default, Encode, Decode, Clone, Copy, PartialEq, Eq)]
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

impl StateCrypto for Aes {
	type Error = Error;

	fn encrypt(&self, data: &mut [u8]) -> Result<()> {
		de_or_encrypt(self, data)
	}

	fn decrypt(&self, data: &mut [u8]) -> Result<()> {
		de_or_encrypt(self, data)
	}
}

impl TryFrom<&Aes> for AesOfb {
	type Error = Error;

	fn try_from(aes: &Aes) -> std::result::Result<Self, Self::Error> {
		AesOfb::new_var(&aes.key, &aes.init_vec).map_err(|_| Error::InvalidNonceKeyLength)
	}
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn de_or_encrypt(aes: &Aes, data: &mut [u8]) -> Result<()> {
	aes.try_into().map(|mut ofb: AesOfb| ofb.apply_keystream(data))
}

#[cfg(feature = "sgx")]
pub use sgx::*;

#[cfg(feature = "sgx")]
pub mod sgx {

	use super::*;
	use itp_settings::files::AES_KEY_FILE_AND_INIT_V;
	use itp_sgx_io::{seal, unseal, SealedIO, StaticSealedIO};
	use log::info;
	use sgx_rand::{Rng, StdRng};
	use std::sgxfs::SgxFile;

	impl StaticSealedIO for AesSeal {
		type Error = Error;
		type Unsealed = Aes;

		fn unseal_from_static_file() -> Result<Self::Unsealed> {
			Ok(unseal(AES_KEY_FILE_AND_INIT_V).map(|b| Decode::decode(&mut b.as_slice()))??)
		}

		fn seal_to_static_file(unsealed: &Self::Unsealed) -> Result<()> {
			Ok(unsealed.using_encoded(|bytes| seal(bytes, AES_KEY_FILE_AND_INIT_V))?)
		}
	}

	impl SealedIO for AesSeal {
		type Error = Error;
		type Unsealed = Aes;

		fn unseal(&self) -> Result<Self::Unsealed> {
			Self::unseal_from_static_file()
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Self::seal_to_static_file(&unsealed)
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
		AesSeal::seal_to_static_file(&Aes::new(key, iv))
	}
}
