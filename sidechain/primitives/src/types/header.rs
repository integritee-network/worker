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
use codec::{Decode, Encode};
use sp_core::H256;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub type ShardIdentifier = H256;

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug, Copy)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Header {
	/// The parent hash.
	pub parent_hash: H256,

	/// The block number.
	pub block_number: u64,

	/// The Shard id.
	pub shard_id: ShardIdentifier,

	/// The payload hash.
	pub payload_hash: H256,
}

impl HeaderTrait for Header {
	type ShardIdentifier = H256;

	/// Get block number.
	fn block_number(&self) -> u64 {
		self.block_number
	}
	/// get parent hash of block
	fn parent_hash(&self) -> H256 {
		self.parent_hash
	}
	/// get shard id of block
	fn shard_id(&self) -> Self::ShardIdentifier {
		self.shard_id
	}
	/// get hash of the block's payload
	fn payload_hash(&self) -> H256 {
		self.payload_hash
	}

	fn new(
		block_number: u64,
		parent_hash: H256,
		shard: Self::ShardIdentifier,
		payload_hash: H256,
	) -> Header {
		Header { block_number, parent_hash, shard_id: shard, payload_hash }
	}
}
