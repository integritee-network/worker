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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::{Error, Result},
	ToPubkey,
};
use itp_sgx_io::SealedIO;
use std::sync::Arc;

/// Access a cryptographic key.
pub trait AccessKey {
	type KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType>;
}

/// Access a cryptographic public key.
pub trait AccessPubkey {
	type KeyType;

	fn retrieve_pubkey(&self) -> Result<Self::KeyType>;
}

/// Mutate a cryptographic key.
pub trait MutateKey<KeyType> {
	fn update_key(&self, key: KeyType) -> Result<()>;
}

/// Repository implementation. Stores a cryptographic key in-memory and in a file backed.
/// Uses the SealedIO trait for the file backend.
pub struct KeyRepository<KeyType, SealedIo> {
	key_lock: RwLock<KeyType>,
	sealed_io: Arc<SealedIo>,
}

impl<KeyType, SealedIo> KeyRepository<KeyType, SealedIo> {
	pub fn new(key: KeyType, sealed_io: Arc<SealedIo>) -> Self {
		KeyRepository { key_lock: RwLock::new(key), sealed_io }
	}
}

impl<KeyType, SealedIo> AccessKey for KeyRepository<KeyType, SealedIo>
where
	KeyType: Clone,
	SealedIo: SealedIO<Unsealed = KeyType, Error = crate::error::Error>,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		self.key_lock.read().map_err(|_| Error::LockPoisoning).map(|l| l.clone())
	}
}

impl<Pair, SealedIo> AccessPubkey for KeyRepository<Pair, SealedIo>
where
	Pair: ToPubkey<Error = crate::error::Error> + Clone,
	SealedIo: SealedIO<Unsealed = Pair, Error = crate::error::Error>,
{
	type KeyType = <Pair as ToPubkey>::Pubkey;

	fn retrieve_pubkey(&self) -> Result<Self::KeyType> {
		self.key_lock.read().map_err(|_| Error::LockPoisoning).map(|p| p.pubkey())?
	}
}

impl<KeyType, SealedIo> MutateKey<KeyType> for KeyRepository<KeyType, SealedIo>
where
	KeyType: Clone,
	SealedIo: SealedIO<Unsealed = KeyType, Error = crate::error::Error>,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut key_lock = self.key_lock.write().map_err(|_| Error::LockPoisoning)?;

		self.sealed_io.seal(&key)?;
		*key_lock = self.sealed_io.unseal()?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{aes::Aes, mocks::AesSealMock};

	type TestKeyRepository = KeyRepository<Aes, AesSealMock>;

	#[test]
	fn update_and_retrieve_key_works() {
		let seal_mock = Arc::new(AesSealMock::default());
		let key_repository = TestKeyRepository::new(seal_mock.unseal().unwrap(), seal_mock.clone());

		assert_eq!(seal_mock.unseal().unwrap(), key_repository.retrieve_key().unwrap());

		let updated_key = Aes::new([2u8; 16], [0u8; 16]);
		key_repository.update_key(updated_key).unwrap();

		assert_eq!(updated_key, key_repository.retrieve_key().unwrap());
		assert_eq!(updated_key, seal_mock.unseal().unwrap());
	}
}
