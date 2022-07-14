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

use crate::{
	error::{Error, Result},
	metadata::{pallet_sidechain::SidechainCallIndexes, pallet_teerex::TeerexCallIndexes},
};
use std::ops::Deref;

/// Trait to get access to the node API metadata.
pub trait AccessNodeMetadata {
	type MetadataType: SidechainCallIndexes + TeerexCallIndexes;

	fn get_from_metadata<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::MetadataType) -> R;
}

/// Repository to manage the node metadata.
///
/// Provides simple means to set the metadata and read from it, guarded by a lock.
#[derive(Default)]
pub struct NodeMetadataRepository<NodeMetadata> {
	metadata_lock: RwLock<Option<NodeMetadata>>,
}

impl<NodeMetadata> NodeMetadataRepository<NodeMetadata>
where
	NodeMetadata: SidechainCallIndexes + TeerexCallIndexes + Default,
{
	pub fn new(metadata: NodeMetadata) -> Self {
		NodeMetadataRepository { metadata_lock: RwLock::new(Some(metadata)) }
	}

	pub fn set_metadata(&self, metadata: NodeMetadata) {
		let mut metadata_lock = self.metadata_lock.write().expect("Lock poisoning");
		*metadata_lock = Some(metadata)
	}
}

impl<NodeMetadata> AccessNodeMetadata for NodeMetadataRepository<NodeMetadata>
where
	NodeMetadata: SidechainCallIndexes + TeerexCallIndexes,
{
	type MetadataType = NodeMetadata;

	fn get_from_metadata<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::MetadataType) -> R,
	{
		match self.metadata_lock.read().expect("Lock poisoning").deref() {
			Some(metadata) => Ok(getter_function(metadata)),
			None => Err(Error::MetadataNotSet),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::metadata::{metadata_mocks::NodeMetadataMock, pallet_teerex::TeerexCallIndexes};
	use std::assert_matches::assert_matches;

	#[test]
	fn get_from_meta_data_returns_error_if_not_set() {
		let repo = NodeMetadataRepository::<NodeMetadataMock>::default();

		assert_matches!(
			repo.get_from_metadata(|m| { m.register_enclave_call_indexes().unwrap() }),
			Err(Error::MetadataNotSet)
		);
	}

	#[test]
	fn get_from_metadata_works() {
		let repo = NodeMetadataRepository::<NodeMetadataMock>::default();
		repo.set_metadata(NodeMetadataMock::new());

		assert_eq!(
			[50, 0],
			repo.get_from_metadata(|m| { m.register_enclave_call_indexes().unwrap() })
				.unwrap()
		);
	}
}
