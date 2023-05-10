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

//! Builder pattern for a parentchain block.

extern crate alloc;

use crate::ParentchainHeaderBuilder;
use alloc::vec::Vec;
use sp_runtime::traits::MaybeSerialize;

pub use itp_types::Header;
pub use sp_runtime::generic::{Block, SignedBlock};

pub struct ParentchainBlockBuilder<Extrinsic> {
	header: Header,
	extrinsics: Vec<Extrinsic>,
}

impl<Extrinsic> Default for ParentchainBlockBuilder<Extrinsic> {
	fn default() -> Self {
		ParentchainBlockBuilder {
			header: ParentchainHeaderBuilder::default().build(),
			extrinsics: Default::default(),
		}
	}
}

impl<Extrinsic: MaybeSerialize> ParentchainBlockBuilder<Extrinsic> {
	pub fn with_header(mut self, header: Header) -> Self {
		self.header = header;
		self
	}

	pub fn with_extrinsics(mut self, extrinsics: Vec<Extrinsic>) -> Self {
		self.extrinsics = extrinsics;
		self
	}

	pub fn build(self) -> Block<Header, Extrinsic> {
		Block { header: self.header, extrinsics: self.extrinsics }
	}

	pub fn build_signed(self) -> SignedBlock<Block<Header, Extrinsic>> {
		SignedBlock { block: self.build(), justifications: None }
	}
}
