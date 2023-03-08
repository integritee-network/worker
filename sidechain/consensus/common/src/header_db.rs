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
use itp_types::H256;
use its_primitives::traits::Header as HeaderT;
use std::{collections::HashMap, convert::From, hash::Hash as HashT};

/// Normally implemented on the `client` in substrate.
/// Is a trait which can offer methods for interfacing with a block Database.
pub trait HeaderDbTrait {
	type Header: HeaderT;
	/// Retrieves Header for the corresponding block hash.
	fn header(&self, hash: &H256) -> Option<Self::Header>;
}

/// A mocked Header Database which allows you to take a Block Hash and Query a Block Header.
pub struct HeaderDb<Hash, Header>(pub HashMap<Hash, Header>);

impl<Hash, Header> HeaderDbTrait for HeaderDb<Hash, Header>
where
	// TODO: the H256 trait bounds are needed because: #1203
	Hash: PartialEq + HashT + Into<H256> + From<H256> + core::cmp::Eq + Clone,
	Header: HeaderT + Clone,
{
	type Header = Header;

	fn header(&self, hash: &H256) -> Option<Self::Header> {
		let header = self.0.get(&Hash::from(*hash))?;
		Some(header.clone())
	}
}
