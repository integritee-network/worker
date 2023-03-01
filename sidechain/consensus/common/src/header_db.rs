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
use its_primitives::{traits::Header as HeaderT, types::header::SidechainHeader};
use std::{collections::HashMap, hash::Hash as HashT};

// Normally implemented on the Client in substrate
pub trait HeaderDbTrait {
	type Header: HeaderT;
	/// Retrieves Header for the corresponding block hash.
	fn header(&self, hash: &H256) -> Option<Self::Header>;
}

/// A mocked Header Database which allows you to take a Block Hash and Query a Block Header.
pub struct HeaderDb<Hash, Header>(pub HashMap<Hash, Header>);
impl<Hash, Header> HeaderDb<Hash, Header>
where
	Hash: PartialEq + Eq + HashT + Clone,
	Header: Clone,
{
	pub fn new() -> Self {
		Self(HashMap::new())
	}

	pub fn insert(&mut self, hash: Hash, header: Header) {
		let _ = self.0.insert(hash, header);
	}
}

impl<Hash, Header> From<&[(Hash, Header)]> for HeaderDb<Hash, Header>
where
	Hash: HashT + Eq + Copy + Clone,
	Header: Copy + Clone,
{
	fn from(items: &[(Hash, Header)]) -> Self {
		let mut header_db = HeaderDb::<Hash, Header>::new();
		for item in items {
			let (hash, header) = item;
			header_db.insert(*hash, *header);
		}
		header_db
	}
}

impl<Hash, Header> HeaderDbTrait for HeaderDb<Hash, Header>
where
	Hash: PartialEq + HashT + Into<H256> + From<H256> + std::cmp::Eq + Clone,
	Header: HeaderT + Clone + Into<SidechainHeader>,
{
	type Header = SidechainHeader;

	fn header(&self, hash: &H256) -> Option<Self::Header> {
		let header = self.0.get(&Hash::from(*hash))?;
		Some(header.clone().into())
	}
}
#[derive(Debug)]
pub enum TestError {
	Error,
}

impl From<()> for TestError {
	fn from(_a: ()) -> Self {
		TestError::Error
	}
}

impl std::fmt::Display for TestError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "TestError")
	}
}

impl std::error::Error for TestError {}
