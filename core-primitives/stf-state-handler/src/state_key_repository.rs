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

use crate::error::{Error, Result};
use itp_sgx_crypto::StateCrypto;
use itp_sgx_io::SealedIO;
use std::sync::Arc;

pub trait AccessStateKey {
	type KeyType: StateCrypto;

	fn retrieve_key(&self) -> Result<Self::KeyType>;
}

pub trait MutateStateKey<KeyType: StateCrypto> {
	fn update_key(&self, key: KeyType) -> Result<()>;
}

pub struct StateKeyRepository<KeyType, SealedIo> {
	key_lock: RwLock<KeyType>,
	sealed_io: Arc<SealedIo>,
}

impl<KeyType, SealedIo> StateKeyRepository<KeyType, SealedIo> {
	pub fn new(key: KeyType, sealed_io: Arc<SealedIo>) -> Self {
		StateKeyRepository { key_lock: RwLock::new(key), sealed_io }
	}
}

impl<KeyType, SealedIo> AccessStateKey for StateKeyRepository<KeyType, SealedIo>
where
	KeyType: StateCrypto + Clone,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		self.key_lock.read().map_err(|_| Error::LockPoisoning).map(|l| l.clone())
	}
}

impl<KeyType, SealedIo> MutateStateKey<KeyType> for StateKeyRepository<KeyType, SealedIo>
where
	KeyType: StateCrypto,
	SealedIo: SealedIO<Unsealed = KeyType, Error = itp_sgx_crypto::Error>,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut key_lock = self.key_lock.write().map_err(|_| Error::LockPoisoning)?;

		self.sealed_io.seal(key)?;
		*key_lock = self.sealed_io.unseal()?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_sgx_crypto::{aes::Aes, mocks::AesSealMock};

	type TestKeyRepository = StateKeyRepository<Aes, AesSealMock>;

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
