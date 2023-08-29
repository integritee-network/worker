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

use super::seal_handler::{SealStateAndKeys, UnsealStateAndKeys};
use crate::error::Result as EnclaveResult;
use itp_types::ShardIdentifier;
use std::{
	sync::{Arc, SgxRwLock as RwLock},
	vec::Vec,
};

#[derive(Clone)]
pub struct SealHandlerMock {
	pub shielding_key: Arc<RwLock<Vec<u8>>>,
	pub state_key: Arc<RwLock<Vec<u8>>>,
	pub state: Arc<RwLock<Vec<u8>>>,
	pub light_client_state: Arc<RwLock<Vec<u8>>>,
}

impl SealHandlerMock {
	pub fn new(
		shielding_key: Arc<RwLock<Vec<u8>>>,
		state_key: Arc<RwLock<Vec<u8>>>,
		state: Arc<RwLock<Vec<u8>>>,
		light_client_state: Arc<RwLock<Vec<u8>>>,
	) -> Self {
		Self { shielding_key, state_key, state, light_client_state }
	}
}

impl SealStateAndKeys for SealHandlerMock {
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		*self.shielding_key.write().unwrap() = bytes.to_vec();
		Ok(())
	}

	fn seal_state_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		*self.state_key.write().unwrap() = bytes.to_vec();
		Ok(())
	}

	fn seal_state(&self, bytes: &[u8], _shard: &ShardIdentifier) -> EnclaveResult<()> {
		*self.state.write().unwrap() = bytes.to_vec();
		Ok(())
	}

	fn seal_new_empty_state(&self, _shard: &ShardIdentifier) -> EnclaveResult<()> {
		Ok(())
	}

	fn seal_light_client_state(&self, bytes: &[u8]) -> EnclaveResult<()> {
		*self.light_client_state.write().unwrap() = bytes.to_vec();
		Ok(())
	}
}

impl UnsealStateAndKeys for SealHandlerMock {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(self.shielding_key.read().unwrap().clone())
	}

	fn unseal_state_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(self.state_key.read().unwrap().clone())
	}

	fn unseal_state(&self, _shard: &ShardIdentifier) -> EnclaveResult<Vec<u8>> {
		Ok(self.state.read().unwrap().clone())
	}

	fn unseal_light_client_state(&self) -> EnclaveResult<Vec<u8>> {
		Ok(self.light_client_state.read().unwrap().clone())
	}
}
