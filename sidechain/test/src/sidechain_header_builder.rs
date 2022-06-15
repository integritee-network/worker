/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

//! Builder pattern for a sidechain header.

use sidechain_primitives::types::{header::SidechainHeader as Header, ShardIdentifier};
use sp_core::H256;

pub struct SidechainHeaderBuilder {
	parent_hash: H256,
	block_number: u64,
	shard_id: ShardIdentifier,
	block_data_hash: H256,
}

impl Default for SidechainHeaderBuilder {
	fn default() -> Self {
		SidechainHeaderBuilder {
			parent_hash: Default::default(),
			block_number: 1,
			shard_id: Default::default(),
			block_data_hash: Default::default(),
		}
	}
}

impl SidechainHeaderBuilder {
	pub fn random() -> Self {
		SidechainHeaderBuilder {
			parent_hash: H256::random(),
			block_number: 42,
			shard_id: ShardIdentifier::random(),
			block_data_hash: H256::random(),
		}
	}

	pub fn with_parent_hash(mut self, parent_hash: H256) -> Self {
		self.parent_hash = parent_hash;
		self
	}

	pub fn with_block_number(mut self, block_number: u64) -> Self {
		self.block_number = block_number;
		self
	}

	pub fn with_shard(mut self, shard_id: ShardIdentifier) -> Self {
		self.shard_id = shard_id;
		self
	}

	pub fn with_block_data_hash(mut self, block_data_hash: H256) -> Self {
		self.block_data_hash = block_data_hash;
		self
	}

	pub fn build(self) -> Header {
		Header {
			parent_hash: self.parent_hash,
			block_number: self.block_number,
			shard_id: self.shard_id,
			block_data_hash: self.block_data_hash,
		}
	}
}
