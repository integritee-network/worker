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
	aes::Aes,
	error::{Error, Result},
	key_repository::{AccessKey, MutateKey},
};
use itp_sgx_io::{SealedIO, StaticSealedIO};
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;

#[derive(Default)]
pub struct KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	key: RwLock<KeyType>,
}

impl<KeyType> KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	pub fn new(key: KeyType) -> Self {
		KeyRepositoryMock { key: RwLock::new(key) }
	}
}

impl<KeyType> AccessKey for KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		Ok(self.key.read().unwrap().clone())
	}
}

impl<KeyType> MutateKey<KeyType> for KeyRepositoryMock<KeyType>
where
	KeyType: Clone + Default,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut lock = self.key.write().unwrap();
		*lock = key;
		Ok(())
	}
}

#[derive(Default)]
pub struct AesSealMock {
	aes: RwLock<Aes>,
}

impl StaticSealedIO for AesSealMock {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(Aes::default())
	}

	fn seal_to_static_file(_unsealed: &Self::Unsealed) -> Result<()> {
		Ok(())
	}
}

impl SealedIO for AesSealMock {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal(&self) -> std::result::Result<Self::Unsealed, Self::Error> {
		self.aes.read().map_err(|e| Error::Other(format!("{:?}", e).into())).map(|k| *k)
	}

	fn seal(&self, unsealed: &Self::Unsealed) -> Result<()> {
		let mut aes_lock = self.aes.write().map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		*aes_lock = *unsealed;
		Ok(())
	}
}

#[derive(Default)]
pub struct Rsa3072SealMock {}

impl StaticSealedIO for Rsa3072SealMock {
	type Error = Error;
	type Unsealed = Rsa3072KeyPair;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(Rsa3072KeyPair::default())
	}

	fn seal_to_static_file(_unsealed: &Self::Unsealed) -> Result<()> {
		Ok(())
	}
}
