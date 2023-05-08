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

//! Builder pattern for a parentchain header.

pub use itp_types::{BlockNumber, Header, H256};
pub use sp_runtime::generic::Digest;

#[derive(Default)]
pub struct ParentchainHeaderBuilder {
	number: BlockNumber,
	parent_hash: H256,
	state_root: H256,
	extrinsic_root: H256,
	digest: Digest,
}

impl ParentchainHeaderBuilder {
	pub fn with_number(mut self, number: BlockNumber) -> Self {
		self.number = number;
		self
	}

	pub fn with_parent_hash(mut self, parent_hash: H256) -> Self {
		self.parent_hash = parent_hash;
		self
	}

	pub fn build(self) -> Header {
		Header {
			number: self.number,
			parent_hash: self.parent_hash,
			state_root: self.state_root,
			extrinsics_root: self.extrinsic_root,
			digest: self.digest,
		}
	}
}
