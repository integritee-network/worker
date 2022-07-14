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

use itp_enclave_api::{direct_request::DirectRequest, EnclaveResult};
use itp_rpc::RpcResponse;
use itp_utils::ToHexPrefixed;
use its_storage::interface::FetchBlocks;
use parity_scale_codec::Encode;
use sidechain_primitives::{
	traits::ShardIdentifierFor,
	types::{BlockHash, SignedBlock, SignedBlock as SignedSidechainBlock},
};

pub struct TestEnclave;

impl DirectRequest for TestEnclave {
	fn rpc(&self, _request: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		Ok(RpcResponse { jsonrpc: "mock_response".into(), result: "null".to_hex(), id: 1 }.encode())
	}
}

pub struct MockSidechainBlockFetcher;

impl FetchBlocks<SignedSidechainBlock> for MockSidechainBlockFetcher {
	fn fetch_all_blocks_after(
		&self,
		_block_hash: &BlockHash,
		_shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> its_storage::Result<Vec<SignedBlock>> {
		Ok(Vec::new())
	}

	fn fetch_blocks_in_range(
		&self,
		_block_hash_from: &BlockHash,
		_block_hash_until: &BlockHash,
		_shard_identifier: &ShardIdentifierFor<SignedBlock>,
	) -> its_storage::Result<Vec<SignedBlock>> {
		Ok(Vec::new())
	}
}
