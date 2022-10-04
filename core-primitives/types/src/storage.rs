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

use codec::{Decode, Encode};
use sp_std::prelude::Vec;

#[derive(Default, Clone, Encode, Decode)]
pub struct StorageEntry<V> {
	pub key: Vec<u8>,
	pub value: Option<V>,
	pub proof: Option<Vec<Vec<u8>>>,
}

/// Contains private fields. We don't expose a public constructor. Hence, the only way
/// to get a `StorageEntryVerified` is via the `VerifyStorageProof` trait.
#[derive(Default, Clone, Encode, Decode)]
pub struct StorageEntryVerified<V> {
	pub key: Vec<u8>,
	pub value: Option<V>,
}

#[cfg(feature = "test")]
impl<V> StorageEntryVerified<V> {
	pub fn new(key: Vec<u8>, value: Option<V>) -> Self {
		Self { key, value }
	}
}

impl<V> StorageEntryVerified<V> {
	pub fn key(&self) -> &[u8] {
		&self.key
	}

	pub fn value(&self) -> &Option<V> {
		&self.value
	}

	/// Without accessing the the field directly but with getters only, we cannot partially
	/// own the struct. So we can't do: `hashmap.insert(self.key(), self.value())` if the getters
	/// consumed the `self`, which is needed to return owned values. Hence, we supply this method,
	/// to consume `self` and be able to use the values individually.
	pub fn into_tuple(self) -> (Vec<u8>, Option<V>) {
		(self.key, self.value)
	}
}
