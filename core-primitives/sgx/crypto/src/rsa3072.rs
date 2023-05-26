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
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	error::{Error, Result},
	traits::{ShieldingCryptoDecrypt, ShieldingCryptoEncrypt},
	ToPubkey,
};
use sgx_crypto_helper::{
	rsa3072::{Rsa3072KeyPair, Rsa3072PubKey},
	RsaKeyPair,
};
use std::vec::Vec;

// Reexport sgx module
#[cfg(feature = "sgx")]
pub use sgx::*;

/// File name of the sealed RSA key file.
pub const RSA3072_SEALED_KEY_FILE: &str = "rsa3072_key_sealed.bin";

impl ShieldingCryptoEncrypt for Rsa3072KeyPair {
	type Error = Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut cipher_buffer = Vec::new();
		self.encrypt_buffer(data, &mut cipher_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(cipher_buffer)
	}
}

impl ShieldingCryptoDecrypt for Rsa3072KeyPair {
	type Error = Error;

	fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut decrypted_buffer = Vec::new();
		self.decrypt_buffer(data, &mut decrypted_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(decrypted_buffer)
	}
}

impl ShieldingCryptoEncrypt for Rsa3072PubKey {
	type Error = Error;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
		let mut cipher_buffer = Vec::new();
		self.encrypt_buffer(data, &mut cipher_buffer)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		Ok(cipher_buffer)
	}
}

impl ToPubkey for Rsa3072KeyPair {
	type Error = Error;
	type Pubkey = Rsa3072PubKey;

	fn pubkey(&self) -> Result<Self::Pubkey> {
		self.export_pubkey().map_err(|e| Error::Other(format!("{:?}", e).into()))
	}
}

pub trait RsaSealing {
	fn unseal_pubkey(&self) -> Result<Rsa3072PubKey>;

	fn unseal_pair(&self) -> Result<Rsa3072KeyPair>;

	fn exists(&self) -> bool;

	fn create_sealed_if_absent(&self) -> Result<()>;

	fn create_sealed(&self) -> Result<()>;
}

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use crate::key_repository::KeyRepository;
	use itp_sgx_io::{seal, unseal, SealedIO};
	use log::*;
	use std::path::PathBuf;

	/// Gets a repository for an Rsa3072 keypair and initializes
	/// a fresh key pair if it doesn't exist at `path`.
	pub fn get_rsa3072_repository(
		path: PathBuf,
	) -> Result<KeyRepository<Rsa3072KeyPair, Rsa3072Seal>> {
		let rsa_seal = Rsa3072Seal::new(path);
		rsa_seal.create_sealed_if_absent()?;
		let shielding_key = rsa_seal.unseal_pair()?;
		Ok(KeyRepository::new(shielding_key, rsa_seal.into()))
	}

	#[derive(Clone, Debug)]
	pub struct Rsa3072Seal {
		base_path: PathBuf,
	}

	impl Rsa3072Seal {
		pub fn new(base_path: PathBuf) -> Self {
			Self { base_path }
		}

		pub fn path(&self) -> PathBuf {
			self.base_path.join(RSA3072_SEALED_KEY_FILE)
		}
	}

	impl RsaSealing for Rsa3072Seal {
		fn unseal_pubkey(&self) -> Result<Rsa3072PubKey> {
			self.unseal()?.pubkey()
		}

		fn unseal_pair(&self) -> Result<Rsa3072KeyPair> {
			self.unseal()
		}

		fn exists(&self) -> bool {
			self.path().exists()
		}

		fn create_sealed_if_absent(&self) -> Result<()> {
			if !self.exists() {
				info!("Keyfile not found, creating new! {}", self.path().display());
				return self.create_sealed()
			}
			Ok(())
		}

		fn create_sealed(&self) -> Result<()> {
			let rsa_keypair =
				Rsa3072KeyPair::new().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			info!("Generated RSA3072 key pair. PubKey: {:?}", rsa_keypair.pubkey()?);
			self.seal(&rsa_keypair)
		}
	}

	impl SealedIO for Rsa3072Seal {
		type Error = Error;
		type Unsealed = Rsa3072KeyPair;

		fn unseal(&self) -> Result<Self::Unsealed> {
			let raw = unseal(self.path())?;
			let key: Rsa3072KeyPair = serde_json::from_slice(&raw)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(key.into())
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			let key_json = serde_json::to_vec(&unsealed)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
			Ok(seal(&key_json, self.path())?)
		}
	}
}

#[cfg(feature = "test")]
pub mod sgx_tests {
	use super::{serde_json, sgx::*};
	use crate::{key_repository::AccessKey, RsaSealing, ToPubkey};
	use itp_sgx_temp_dir::TempDir;
	use sgx_crypto_helper::rsa3072::Rsa3072PubKey;

	/// Helper method because Rsa3072 does not implement `Eq`.
	pub fn equal(pubkey1: &Rsa3072PubKey, pubkey2: &Rsa3072PubKey) -> bool {
		serde_json::to_vec(pubkey1).unwrap() == serde_json::to_vec(pubkey2).unwrap()
	}

	pub fn using_get_rsa3072_repository_twice_initializes_key_only_once() {
		let temp_dir =
			TempDir::with_prefix("using_get_rsa3072_repository_twice_initializes_key_only_once")
				.unwrap();
		let temp_path = temp_dir.path().to_path_buf();
		let key1 = get_rsa3072_repository(temp_path.clone()).unwrap().retrieve_key().unwrap();
		let key2 = get_rsa3072_repository(temp_path).unwrap().retrieve_key().unwrap();
		assert!(equal(&key1.pubkey().unwrap(), &key2.pubkey().unwrap()));
	}

	pub fn rsa3072_sealing_works() {
		let temp_dir = TempDir::with_prefix("rsa3072_sealing_works").unwrap();
		let seal = Rsa3072Seal::new(temp_dir.path().to_path_buf());

		// Create new sealed keys and unseal them
		assert!(!seal.exists());
		seal.create_sealed_if_absent().unwrap();
		let pair = seal.unseal_pair().unwrap();
		let pubkey = seal.unseal_pubkey().unwrap();

		assert!(seal.exists());
		assert!(equal(&pair.pubkey().unwrap(), &pubkey));

		// Should not change anything because the key is already there.
		seal.create_sealed_if_absent().unwrap();
		let pair_same = seal.unseal_pair().unwrap();

		assert!(equal(&pair.pubkey().unwrap(), &pair_same.pubkey().unwrap()));

		// Should overwrite previous keys.
		seal.create_sealed().unwrap();
		let pair_different = seal.unseal_pair().unwrap();

		assert!(!equal(&pair_different.pubkey().unwrap(), &pair.pubkey().unwrap()));
	}
}
