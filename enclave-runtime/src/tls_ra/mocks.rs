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

use super::key_handler::{SealKeys, UnsealKeys};
use crate::error::Result as EnclaveResult;
use lazy_static::lazy_static;
use std::{sync::SgxRwLock as RwLock, vec::Vec};

lazy_static! {
	pub static ref SHIELDING_KEY: RwLock<Vec<u8>> = RwLock::new(vec![]);
	pub static ref SIGNING_KEY: RwLock<Vec<u8>> = RwLock::new(vec![]);
}

#[derive(Clone)]
pub struct KeyHandlerMock {
	pub shielding_key: Vec<u8>,
	pub signing_key: Vec<u8>,
}

impl KeyHandlerMock {
	pub fn new(shielding_key: Vec<u8>, signing_key: Vec<u8>) -> Self {
		KeyHandlerMock { shielding_key, signing_key }
	}
}

impl SealKeys for KeyHandlerMock {
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		*SHIELDING_KEY.write().unwrap() = bytes.to_vec();
		Ok(())
	}

	fn seal_signing_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		*SIGNING_KEY.write().unwrap() = bytes.to_vec();
		Ok(())
	}
}

impl UnsealKeys for KeyHandlerMock {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(self.shielding_key.clone())
	}

	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(self.signing_key.clone())
	}
}
