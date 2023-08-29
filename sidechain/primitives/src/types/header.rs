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

//!Primitives for the sidechain
use crate::traits::Header as HeaderTrait;
use codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::H256;
use sp_runtime::traits::{BlakeTwo256, Hash};
use sp_std::prelude::*;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

pub use itp_types::ShardIdentifier;

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug, Copy, Default, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct SidechainHeader {
	/// The parent hash.
	pub parent_hash: H256,

	/// The block number.
	pub block_number: u64,

	/// The Shard id.
	pub shard_id: ShardIdentifier,

	/// The payload hash.
	pub block_data_hash: H256,

	/// The latest finalized block number
	pub next_finalization_block_number: u64,
}

impl SidechainHeader {
	/// get the `blake2_256` hash of the header.
	pub fn hash(&self) -> H256 {
		self.using_encoded(BlakeTwo256::hash)
	}
}

impl HeaderTrait for SidechainHeader {
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
	fn next_finalization_block_number(&self) -> u64 {
		self.next_finalization_block_number
	}

	fn new(
		block_number: u64,
		parent_hash: H256,
		shard: Self::ShardIdentifier,
		block_data_hash: H256,
		next_finalization_block_number: u64,
	) -> SidechainHeader {
		SidechainHeader {
			block_number,
			parent_hash,
			shard_id: shard,
			block_data_hash,
			next_finalization_block_number,
		}
	}
}
