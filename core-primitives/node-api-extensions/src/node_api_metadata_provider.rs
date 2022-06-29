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

#[derive(Default, Encode, Decode, Debug)]
pub struct DummyMetadata {
	version: u32,
}

pub type NodeApiMetadata = DummyMetadata;

/// Trait to get access to the node API metadata.
pub trait AccessNodeApiMetadata {
	type MetadataType;

	fn get_from_metadata<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::MetadataType) -> R;
}

#[derive(Default)]
pub struct NodeApiMetadataRepository {
	metadata_lock: RwLock<Option<NodeApiMetadata>>,
}

impl NodeApiMetadataRepository {
	pub fn set_metadata(&self, metadata: NodeApiMetadata) {
		let mut metadata_lock = self.metadata_lock.write().unwrap();
		*metadata_lock = Some(metadata)
	}
}

impl AccessNodeApiMetadata for NodeApiMetadataRepository {
	type MetadataType = NodeApiMetadata;

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
		let repo = NodeApiMetadataRepository::default();

		assert_matches!(repo.get_from_metadata(|m| { m.version }), Err(Error::MetadataNotSet));
	}

	#[test]
	fn get_from_metadata_works() {
		let repo = NodeApiMetadataRepository::default();
		repo.set_metadata(NodeApiMetadata { version: 42 });

		assert_eq!(42, repo.get_from_metadata(|m| { m.version }).unwrap());
	}
}
