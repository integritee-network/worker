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

use itp_sgx_crypto::{
	error::Result,
	key_repository::{AccessKey, MutateKey},
	StateCrypto,
};

#[derive(Default)]
pub struct StateKeyRepositoryMock<KeyType>
where
	KeyType: StateCrypto + Clone + Default,
{
	key: RwLock<KeyType>,
}

impl<KeyType> StateKeyRepositoryMock<KeyType>
where
	KeyType: StateCrypto + Clone + Default,
{
	#[cfg(all(feature = "test", feature = "sgx"))]
	pub fn new(key: KeyType) -> Self {
		StateKeyRepositoryMock { key: RwLock::new(key) }
	}
}

impl<KeyType> AccessKey for StateKeyRepositoryMock<KeyType>
where
	KeyType: StateCrypto + Clone + Default,
{
	type KeyType = KeyType;

	fn retrieve_key(&self) -> Result<Self::KeyType> {
		Ok(self.key.read().unwrap().clone())
	}
}

impl<KeyType> MutateKey<KeyType> for StateKeyRepositoryMock<KeyType>
where
	KeyType: StateCrypto + Clone + Default,
{
	fn update_key(&self, key: KeyType) -> Result<()> {
		let mut lock = self.key.write().unwrap();
		*lock = key;
		Ok(())
	}
}
