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

use crate::{
	sidechain_block_data_builder::SidechainBlockDataBuilder,
	sidechain_header_builder::SidechainHeaderBuilder,
};
use sidechain_primitives::{
	traits::SignBlock,
	types::{block_data::BlockData, header::SidechainHeader as Header, Block, SignedBlock},
};
use sp_core::{ed25519, Pair};

type Seed = [u8; 32];
const ENCLAVE_SEED: Seed = *b"12345678901234567890123456789012";

pub struct SidechainBlockBuilder {
	signer: ed25519::Pair,
	header: Header,
	block_data: BlockData,
}

impl Default for SidechainBlockBuilder {
	fn default() -> Self {
		SidechainBlockBuilder {
			signer: Pair::from_seed(&ENCLAVE_SEED),
			header: SidechainHeaderBuilder::default().build(),
			block_data: SidechainBlockDataBuilder::default().build(),
		}
	}
}

impl SidechainBlockBuilder {
	pub fn random() -> Self {
		SidechainBlockBuilder {
			signer: Pair::from_seed(&ENCLAVE_SEED),
			header: SidechainHeaderBuilder::random().build(),
			block_data: SidechainBlockDataBuilder::random().build(),
		}
	}

	pub fn with_header(mut self, header: Header) -> Self {
		self.header = header;
		self
	}

	pub fn with_block_data(mut self, block_data: BlockData) -> Self {
		self.block_data = block_data;
		self
	}

	pub fn with_signer(mut self, signer: ed25519::Pair) -> Self {
		self.signer = signer;
		self
	}

	pub fn build(self) -> Block {
		Block { header: self.header, block_data: self.block_data }
	}

	pub fn build_signed(self) -> SignedBlock {
		let signer = self.signer.clone();
		self.build().sign_block(&signer)
	}
}

#[test]
fn build_signed_block_has_valid_signature() {
	use sidechain_primitives::traits::SignedBlock as SignedBlockTrait;

	let signed_block = SidechainBlockBuilder::default().build_signed();
	assert!(signed_block.verify_signature());
}
