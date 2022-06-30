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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::error::{Error, Result};
use codec::{Decode, Encode};
use std::ops::Deref;

#[derive(Default, Encode, Decode, Debug, Clone)]
pub struct DummyMetadata {
	pub teerex_module: u8,
	pub register_enclave: u8,
	pub call_worker: u8,
	pub processed_parentchain_block: u8,
	pub shield_funds: u8,
	pub unshield_funds: u8,
	pub sidechain_module: u8,
	pub proposed_sidechain_block: u8,
	pub runtime_spec_version: u32,
	pub runtime_transaction_version: u32,
}

impl DummyMetadata {
	pub fn new() -> Self {
		DummyMetadata {
			teerex_module: 50u8,
			register_enclave: 0u8,
			call_worker: 2u8,
			processed_parentchain_block: 3u8,
			shield_funds: 4u8,
			unshield_funds: 5u8,
			sidechain_module: 53u8,
			proposed_sidechain_block: 0u8,
			runtime_spec_version: 24,
			runtime_transaction_version: 3,
		}
	}
}

// TODO @echevrier: Instead of the type alias, use your real metadata struct
pub type NodeMetadata = DummyMetadata;

/// Trait to get access to the node API metadata.
pub trait AccessNodeMetadata {
	type MetadataType;

	fn get_from_metadata<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::MetadataType) -> R;
}

#[derive(Default)]
pub struct NodeMetadataRepository {
	metadata_lock: RwLock<Option<NodeMetadata>>,
}

impl NodeMetadataRepository {
	pub fn new(metadata: NodeMetadata) -> Self {
		NodeMetadataRepository { metadata_lock: RwLock::new(Some(metadata)) }
	}

	pub fn set_metadata(&self, metadata: NodeMetadata) {
		let mut metadata_lock = self.metadata_lock.write().unwrap();
		*metadata_lock = Some(metadata)
	}
}

impl AccessNodeMetadata for NodeMetadataRepository {
	type MetadataType = NodeMetadata;

	fn get_from_metadata<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::MetadataType) -> R,
	{
		match self.metadata_lock.read().unwrap().deref() {
			Some(metadata) => Ok(getter_function(metadata)),
			None => Err(Error::MetadataNotSet),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::assert_matches::assert_matches;

	#[test]
	fn get_from_meta_data_returns_error_if_not_set() {
		let repo = NodeMetadataRepository::default();

		assert_matches!(
			repo.get_from_metadata(|m| { m.teerex_module }),
			Err(Error::MetadataNotSet)
		);
	}

	#[test]
	fn get_from_metadata_works() {
		let repo = NodeMetadataRepository::default();
		repo.set_metadata(NodeMetadata::new());

		assert_eq!(50, repo.get_from_metadata(|m| { m.teerex_module }).unwrap());
	}
}
