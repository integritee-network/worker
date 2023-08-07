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

use crate::{pallet_teerex::PalletTeerexApi, ApiResult};
use itp_types::{parentchain::Hash, AccountId, IpfsHash, MultiEnclave, ShardIdentifier};
use std::collections::HashMap;

#[derive(Default)]
pub struct PalletTeerexApiMock {
	registered_enclaves: HashMap<AccountId, MultiEnclave<Vec<u8>>>,
}

impl PalletTeerexApiMock {
	pub fn with_enclaves(mut self, enclaves: Vec<MultiEnclave<Vec<u8>>>) -> Self {
		enclaves.iter().map(|enclave| self.registered_enclaves.insert(enclave));
		self
	}
}

impl PalletTeerexApi for PalletTeerexApiMock {
	fn enclave(
		&self,
		account: AccountId,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
		Ok(self.registered_enclaves.get(index as usize).cloned())
	}

	fn enclave_count(&self, _at_block: Option<Hash>) -> ApiResult<u64> {
		Ok(self.registered_enclaves.len() as u64)
	}

	fn all_enclaves(&self, _at_block: Option<Hash>) -> ApiResult<Vec<MultiEnclave<Vec<u8>>>> {
		Ok(self.registered_enclaves.clone())
	}

	fn primary_worker_for_shard(
		&self,
		_shard: &ShardIdentifier,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
		todo!()
	}

	fn latest_ipfs_hash(
		&self,
		_shard: &ShardIdentifier,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<IpfsHash>> {
		todo!()
	}
}
