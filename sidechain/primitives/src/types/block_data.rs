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

use crate::traits::BlockData as BlockDataTrait;
use codec::{Decode, Encode};
use sp_core::{ed25519, H256};
use sp_std::vec::Vec;

pub type Timestamp = u64;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct BlockData {
	pub timestamp: u64,
	/// Parentchain header this block is based on.
	pub layer_one_head: H256,
	/// Must be registered on layer one as an enclave for the respective shard.
	pub block_author: ed25519::Public,
	/// Hashes of signed trusted operations.
	pub signed_top_hashes: Vec<H256>,
	/// Encrypted state payload.
	pub encrypted_state_diff: Vec<u8>,
}

impl BlockDataTrait for BlockData {
	type Public = ed25519::Public;

	/// Get timestamp of block.
	fn timestamp(&self) -> Timestamp {
		self.timestamp
	}
	/// Get layer one head of block.
	fn layer_one_head(&self) -> H256 {
		self.layer_one_head
	}
	/// Get author of block.
	fn block_author(&self) -> &Self::Public {
		&self.block_author
	}
	/// Get reference of extrinisics of block.
	fn signed_top_hashes(&self) -> &[H256] {
		&self.signed_top_hashes
	}
	/// Get encrypted payload.
	fn encrypted_state_diff(&self) -> &Vec<u8> {
		&self.encrypted_state_diff
	}
	/// Constructs block data.
	fn new(
		block_author: Self::Public,
		layer_one_head: H256,
		signed_top_hashes: Vec<H256>,
		encrypted_state_diff: Vec<u8>,
		timestamp: Timestamp,
	) -> BlockData {
		// create block
		BlockData {
			timestamp,
			layer_one_head,
			signed_top_hashes,
			block_author,
			encrypted_state_diff,
		}
	}
}
