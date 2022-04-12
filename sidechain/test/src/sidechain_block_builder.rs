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

//! Builder pattern for a signed sidechain block.

use codec::Encode;
use itp_time_utils;
use itp_types::H256;
use its_primitives::{
	traits::{Block as BlockTrait, BlockData as BlockDataTrait, Header as HeaderTrait, SignBlock},
	types::{
		block::{BlockHash, BlockNumber, Timestamp},
		Block, ShardIdentifier, SignedBlock,
	},
};
use sp_core::{ed25519, Pair};
use sp_runtime::traits::{BlakeTwo256, Hash};

type Seed = [u8; 32];
const ENCLAVE_SEED: Seed = *b"12345678901234567890123456789012";

pub struct SidechainBlockBuilder {
	signer: ed25519::Pair,
	number: BlockNumber,
	parent_hash: BlockHash,
	parentchain_block_hash: H256,
	signed_top_hashes: Vec<H256>,
	encrypted_payload: Vec<u8>,
	shard: ShardIdentifier,
	timestamp: Timestamp,
}

impl Default for SidechainBlockBuilder {
	fn default() -> Self {
		SidechainBlockBuilder {
			signer: Pair::from_seed(&ENCLAVE_SEED),
			number: 1,
			parent_hash: BlockHash::default(),
			parentchain_block_hash: Default::default(),
			signed_top_hashes: Default::default(),
			encrypted_payload: Default::default(),
			shard: Default::default(),
			timestamp: Default::default(),
		}
	}
}

impl SidechainBlockBuilder {
	pub fn random() -> Self {
		SidechainBlockBuilder {
			signer: Pair::from_seed(&ENCLAVE_SEED),
			number: 42,
			parent_hash: BlockHash::random(),
			parentchain_block_hash: BlockHash::random(),
			signed_top_hashes: vec![H256::random(), H256::random()],
			encrypted_payload: vec![1, 3, 42, 8, 11, 33],
			shard: ShardIdentifier::random(),
			timestamp: itp_time_utils::now_as_u64(),
		}
	}
	pub fn with_signer(mut self, signer: ed25519::Pair) -> Self {
		self.signer = signer;
		self
	}

	pub fn with_number(mut self, number: BlockNumber) -> Self {
		self.number = number;
		self
	}

	pub fn with_parent_hash(mut self, parent_hash: BlockHash) -> Self {
		self.parent_hash = parent_hash;
		self
	}

	pub fn with_parentchain_block_hash(mut self, parentchain_block_hash: H256) -> Self {
		self.parentchain_block_hash = parentchain_block_hash;
		self
	}

	pub fn with_signed_top_hashes(mut self, signed_top_hashes: Vec<H256>) -> Self {
		self.signed_top_hashes = signed_top_hashes;
		self
	}

	pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
		self.encrypted_payload = payload;
		self
	}

	pub fn with_shard(mut self, shard: ShardIdentifier) -> Self {
		self.shard = shard;
		self
	}

	pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
		self.timestamp = timestamp;
		self
	}

	/// Calculate the payload of a sidechain block.
	pub fn block_data_hash(&self) -> H256 {
		(
			self.timestamp,
			self.parentchain_block_hash,
			self.signer.public(),
			self.signed_top_hashes.as_slice(),
			self.encrypted_payload.as_slice(),
		)
			.using_encoded(BlakeTwo256::hash)
	}

	pub fn build(&self) -> Block {
		let block_data_hash = self.block_data_hash();

		let header = HeaderTrait::new(self.number, self.parent_hash, self.shard, block_data_hash);

		let block_data = BlockDataTrait::new(
			self.signer.public(),
			self.parentchain_block_hash,
			self.signed_top_hashes.clone(),
			self.encrypted_payload.clone(),
			self.timestamp,
		);

		Block::new(header, block_data)
	}

	pub fn build_signed(&self) -> SignedBlock {
		let signer = &self.signer.clone();
		self.build().sign_block(signer)
	}
}

#[test]
fn build_signed_block_has_valid_signature() {
	use its_primitives::traits::SignedBlock as SignedBlockTrait;

	let signed_block = SidechainBlockBuilder::default().build_signed();
	assert!(signed_block.verify_signature());
}
