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

//! Builder pattern for sidechain block data.

use itp_types::H256;
use its_primitives::types::{
	block::{BlockHash, Timestamp},
	block_data::BlockData,
};
use sp_core::{ed25519, Pair};
use std::{time::SystemTime, vec};

type Seed = [u8; 32];
const ENCLAVE_SEED: Seed = *b"12345678901234567890123456789012";

pub struct SidechainBlockDataBuilder {
	timestamp: Timestamp,
	layer_one_head: H256,
	signer: ed25519::Pair,
	signed_top_hashes: Vec<H256>,
	encrypted_state_diff: Vec<u8>,
}

impl Default for SidechainBlockDataBuilder {
	fn default() -> Self {
		SidechainBlockDataBuilder {
			timestamp: Default::default(),
			layer_one_head: Default::default(),
			signer: Pair::from_seed(&ENCLAVE_SEED),
			signed_top_hashes: Default::default(),
			encrypted_state_diff: Default::default(),
		}
	}
}

impl SidechainBlockDataBuilder {
	pub fn random() -> Self {
		SidechainBlockDataBuilder {
			timestamp: now_as_millis(),
			layer_one_head: BlockHash::random(),
			signer: Pair::from_seed(&ENCLAVE_SEED),
			signed_top_hashes: vec![H256::random(), H256::random()],
			encrypted_state_diff: vec![1, 3, 42, 8, 11, 33],
		}
	}

	pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
		self.timestamp = timestamp;
		self
	}

	pub fn with_signer(mut self, signer: ed25519::Pair) -> Self {
		self.signer = signer;
		self
	}

	pub fn with_layer_one_head(mut self, layer_one_head: H256) -> Self {
		self.layer_one_head = layer_one_head;
		self
	}

	pub fn with_signed_top_hashes(mut self, signed_top_hashes: Vec<H256>) -> Self {
		self.signed_top_hashes = signed_top_hashes;
		self
	}

	pub fn with_payload(mut self, payload: Vec<u8>) -> Self {
		self.encrypted_state_diff = payload;
		self
	}

	pub fn build(self) -> BlockData {
		BlockData {
			timestamp: self.timestamp,
			block_author: self.signer.public(),
			layer_one_head: self.layer_one_head,
			signed_top_hashes: self.signed_top_hashes,
			encrypted_state_diff: self.encrypted_state_diff,
		}
	}
}

/// gets the timestamp of the block as seconds since unix epoch
fn now_as_millis() -> u64 {
	SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis() as u64
}
