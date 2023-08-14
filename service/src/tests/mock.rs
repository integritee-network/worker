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

use codec::Encode;
use itp_node_api::api_client::{ApiResult, PalletTeerexApi};
use itp_types::{
	AccountId, MultiEnclave, SgxBuildMode, SgxEnclave, SgxReportData, SgxStatus, ShardIdentifier,
	H256 as Hash,
};

pub struct TestNodeApi;

pub const W1_URL: &str = "127.0.0.1:22222";
pub const W2_URL: &str = "127.0.0.1:33333";

pub fn enclaves() -> Vec<MultiEnclave<Vec<u8>>> {
	vec![
		MultiEnclave::from(
			SgxEnclave::new(
				SgxReportData::default(),
				[1; 32],
				[1; 32],
				1,
				SgxBuildMode::Production,
				SgxStatus::Ok,
			)
			.with_url(format!("wss://{}", W1_URL).encode()),
		),
		MultiEnclave::from(
			SgxEnclave::new(
				SgxReportData::default(),
				[2; 32],
				[2; 32],
				2,
				SgxBuildMode::Production,
				SgxStatus::Ok,
			)
			.with_url(format!("wss://{}", W2_URL).encode()),
		),
	]
}

impl PalletTeerexApi for TestNodeApi {
	fn enclave(
		&self,
		_account: &AccountId,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
		Ok(Some(enclaves().remove(0)))
	}
	fn enclave_count(&self, _at_block: Option<Hash>) -> ApiResult<u64> {
		unreachable!()
	}

	fn all_enclaves(&self, _at_block: Option<Hash>) -> ApiResult<Vec<MultiEnclave<Vec<u8>>>> {
		Ok(enclaves())
	}

	fn primary_worker_for_shard(
		&self,
		_: &ShardIdentifier,
		_at_block: Option<Hash>,
	) -> ApiResult<Option<MultiEnclave<Vec<u8>>>> {
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
