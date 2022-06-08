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

use crate::traits::Header as HeaderTrait;
use sidechain_primitives::SidechainHeader as Header;
use sp_core::H256;

pub type ShardIdentifier = H256;

impl HeaderTrait for Header {
	type ShardIdentifier = H256;

	fn block_number(&self) -> u64 {
		self.block_number
	}
	fn parent_hash(&self) -> H256 {
		self.parent_hash
	}
	fn shard_id(&self) -> Self::ShardIdentifier {
		self.shard_id
	}
	fn block_data_hash(&self) -> H256 {
		self.block_data_hash
	}

	fn new(
		block_number: u64,
		parent_hash: H256,
		shard: Self::ShardIdentifier,
		block_data_hash: H256,
	) -> Header {
		Header { block_number, parent_hash, shard_id: shard, block_data_hash }
	}
}
