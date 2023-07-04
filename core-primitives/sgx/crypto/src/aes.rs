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
use ofb::{
	cipher::{NewStreamCipher, SyncStreamCipher},
	Ofb,
};
use std::{
	convert::{TryFrom, TryInto},
	path::PathBuf,
};

type AesOfb = Ofb<Aes128>;

/// File name of the sealed AES key data.
pub const AES_KEY_FILE_AND_INIT_V: &str = "aes_key_and_iv_sealed_data.bin";

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

#[derive(Clone, Debug)]
pub struct AesSeal {
	base_path: PathBuf,
}

impl AesSeal {
	pub fn new(base_path: PathBuf) -> Self {
		Self { base_path }
	}

	pub fn path(&self) -> PathBuf {
		self.base_path.join(AES_KEY_FILE_AND_INIT_V)
	}
}

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

pub trait AesSealing {
	fn unseal_key(&self) -> Result<Aes>;

	fn exists(&self) -> bool;

	fn create_sealed_if_absent(&self) -> Result<()>;

	fn create_sealed(&self) -> Result<()>;
}

#[cfg(feature = "sgx")]
pub use sgx::*;

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use crate::key_repository::KeyRepository;
	use itp_sgx_io::{seal, unseal, SealedIO};
	use log::info;
	use sgx_rand::{Rng, StdRng};
	use std::sgxfs::SgxFile;

	/// Gets a repository for an AES key and initializes
	/// a fresh key if it doesn't exist at `path`.
	pub fn get_aes_repository(path: PathBuf) -> Result<KeyRepository<Aes, AesSeal>> {
		let aes_seal = AesSeal::new(path);
		aes_seal.create_sealed_if_absent()?;
		let aes_key = aes_seal.unseal_key()?;
		Ok(KeyRepository::new(aes_key, aes_seal.into()))
	}

	impl AesSealing for AesSeal {
		fn unseal_key(&self) -> Result<Aes> {
			self.unseal()
		}

		fn exists(&self) -> bool {
			SgxFile::open(self.path()).is_ok()
		}

		fn create_sealed_if_absent(&self) -> Result<()> {
			if !self.exists() {
				info!("Keyfile not found, creating new! {}", self.path().display());
				return self.create_sealed()
			}
			Ok(())
		}

		fn create_sealed(&self) -> Result<()> {
			let mut key = [0u8; 16];
			let mut iv = [0u8; 16];
			let mut rand = StdRng::new()?;

			rand.fill_bytes(&mut key);
			rand.fill_bytes(&mut iv);

			Ok(self.seal(&Aes::new(key, iv))?)
		}
	}

	impl SealedIO for AesSeal {
		type Error = Error;
		type Unsealed = Aes;

		fn unseal(&self) -> Result<Self::Unsealed> {
			Ok(unseal(self.path()).map(|b| Decode::decode(&mut b.as_slice()))??)
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Ok(unsealed.using_encoded(|bytes| seal(bytes, self.path()))?)
		}
	}
}

#[cfg(feature = "test")]
pub mod sgx_tests {
	use super::sgx::*;
	use crate::{key_repository::AccessKey, AesSeal, AesSealing};
	use itp_sgx_temp_dir::TempDir;

	pub fn using_get_aes_repository_twice_initializes_key_only_once() {
		let temp_dir =
			TempDir::with_prefix("using_get_aes_repository_twice_initializes_key_only_once")
				.unwrap();
		let temp_path = temp_dir.path().to_path_buf();
		let key1 = get_aes_repository(temp_path.clone()).unwrap().retrieve_key().unwrap();
		let key2 = get_aes_repository(temp_path).unwrap().retrieve_key().unwrap();
		assert_eq!(key1, key2);
	}

	pub fn aes_sealing_works() {
		let temp_dir = TempDir::with_prefix("aes_sealing_works").unwrap();
		let seal = AesSeal::new(temp_dir.path().to_path_buf());

		// Create new sealed keys and unseal them
		assert!(!seal.exists());
		seal.create_sealed_if_absent().unwrap();
		let key = seal.unseal_key().unwrap();

		assert!(seal.exists());

		// Should not change anything because the key is already there.
		seal.create_sealed_if_absent().unwrap();
		let key_same = seal.unseal_key().unwrap();

		assert_eq!(key, key_same);

		// Should overwrite previous keys.
		seal.create_sealed().unwrap();
		let key_different = seal.unseal_key().unwrap();

		assert_ne!(key_different, key);
	}
}
