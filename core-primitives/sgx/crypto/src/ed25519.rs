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
	ToPubkey,
};
use sp_core::ed25519;

#[cfg(feature = "sgx")]
pub use sgx::*;

/// File name of the sealed Ed25519 seed file.
pub const SEALED_SIGNER_SEED_FILE: &str = "ed25519_key_sealed.bin";

pub trait Ed25519Sealing {
	fn unseal_pubkey(&self) -> Result<ed25519::Public>;

	fn unseal_pair(&self) -> Result<ed25519::Pair>;

	fn exists(&self) -> bool;

	fn create_sealed_if_absent(&self) -> Result<()>;

	fn create_sealed(&self) -> Result<()>;
}

impl ToPubkey for ed25519::Pair {
	type Error = Error;
	type Pubkey = ed25519::Public;

	fn pubkey(&self) -> Result<Self::Pubkey> {
		Ok((*self).into())
	}
}

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::SEALED_SIGNER_SEED_FILE;
	use crate::{
		error::{Error, Result},
		key_repository::KeyRepository,
		Ed25519Sealing,
	};
	use codec::Encode;
	use itp_sgx_io::{seal, unseal, SealedIO};
	use log::*;
	use sgx_rand::{Rng, StdRng};
	use sp_core::{crypto::Pair, ed25519};
	use std::path::PathBuf;

	/// Gets a repository for an Ed25519 keypair and initializes
	/// a fresh key pair if it doesn't exist at `path`.
	pub fn get_ed25519_repository(
		path: PathBuf,
	) -> Result<KeyRepository<ed25519::Pair, Ed25519Seal>> {
		let ed25519_seal = Ed25519Seal::new(path);
		ed25519_seal.create_sealed_if_absent()?;
		let signing_pair = ed25519_seal.unseal_pair()?;
		Ok(KeyRepository::new(signing_pair, ed25519_seal.into()))
	}

	#[derive(Clone, Debug)]
	pub struct Ed25519Seal {
		base_path: PathBuf,
	}

	impl Ed25519Seal {
		pub fn new(base_path: PathBuf) -> Self {
			Self { base_path }
		}

		pub fn path(&self) -> PathBuf {
			self.base_path.join(SEALED_SIGNER_SEED_FILE)
		}
	}

	impl Ed25519Sealing for Ed25519Seal {
		fn unseal_pubkey(&self) -> Result<ed25519::Public> {
			self.unseal().map(Into::into)
		}

		fn unseal_pair(&self) -> Result<ed25519::Pair> {
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
			let mut seed = [0u8; 32];
			let mut rand = StdRng::new()?;
			rand.fill_bytes(&mut seed);

			Ok(seal(&seed, self.path())?)
		}
	}

	impl SealedIO for Ed25519Seal {
		type Error = Error;
		type Unsealed = ed25519::Pair;

		fn unseal(&self) -> Result<Self::Unsealed> {
			let raw = unseal(self.path())?;

			ed25519::Pair::from_seed_slice(&raw)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))
		}

		fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
			Ok(unsealed.seed().using_encoded(|bytes| seal(bytes, self.path()))?)
		}
	}
}

#[cfg(feature = "test")]
pub mod sgx_tests {
	use super::sgx::*;
	use crate::{key_repository::AccessKey, Ed25519Sealing, ToPubkey};
	use itp_sgx_temp_dir::TempDir;

	pub fn using_get_ed25519_repository_twice_initializes_key_only_once() {
		let temp_dir =
			TempDir::with_prefix("using_get_rsa3072_repository_twice_initializes_key_only_once")
				.unwrap();
		let temp_path = temp_dir.path().to_path_buf();
		let key1 = get_ed25519_repository(temp_path.clone()).unwrap().retrieve_key().unwrap();
		let key2 = get_ed25519_repository(temp_path).unwrap().retrieve_key().unwrap();
		assert_eq!(key1.pubkey().unwrap(), key2.pubkey().unwrap());
	}

	pub fn ed25529_sealing_works() {
		let temp_dir = TempDir::with_prefix("ed25529_sealing_works").unwrap();
		let seal = Ed25519Seal::new(temp_dir.path().to_path_buf());

		// Create new sealed keys and unseal them.
		assert!(!seal.exists());
		seal.create_sealed_if_absent().unwrap();
		let pair = seal.unseal_pair().unwrap();
		let pubkey = seal.unseal_pubkey().unwrap();

		assert!(seal.exists());
		assert_eq!(pair.pubkey().unwrap(), pubkey);

		// Should not change anything because the key is already there.
		seal.create_sealed_if_absent().unwrap();
		let pair_same = seal.unseal_pair().unwrap();

		assert_eq!(pair.pubkey().unwrap(), pair_same.pubkey().unwrap());

		// Should overwrite previous keys.
		seal.create_sealed().unwrap();
		let pair_different = seal.unseal_pair().unwrap();

		assert_ne!(pair_different.pubkey().unwrap(), pair.pubkey().unwrap());
	}
}
