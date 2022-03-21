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

use itp_node_api_extensions::{ApiResult, PalletTeerexApi};
use itp_types::{Enclave, ShardIdentifier, H256 as Hash};

pub struct TestNodeApi;

pub const W1_URL: &str = "127.0.0.1:22222";
pub const W2_URL: &str = "127.0.0.1:33333";

pub fn enclaves() -> Vec<Enclave> {
	vec![
		Enclave::new([0; 32].into(), [1; 32], 1, format!("wss://{}", W1_URL)),
		Enclave::new([2; 32].into(), [3; 32], 2, format!("wss://{}", W2_URL)),
	]
}

impl PalletTeerexApi for TestNodeApi {
	fn enclave(&self, index: u64, _at_block: Option<Hash>) -> ApiResult<Option<Enclave>> {
		Ok(Some(enclaves().remove(index as usize)))
	}
	fn enclave_count(&self, _at_block: Option<Hash>) -> ApiResult<u64> {
		unreachable!()
	}

	fn all_enclaves(&self, _at_block: Option<Hash>) -> ApiResult<Vec<Enclave>> {
		Ok(enclaves())
	}

	fn worker_for_shard(
		&self,
		_: &ShardIdentifier,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<Enclave>> {
		unreachable!()
	}
	fn latest_ipfs_hash(
		&self,
		_: &ShardIdentifier,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<[u8; 46]>> {
		unreachable!()
	}
}
