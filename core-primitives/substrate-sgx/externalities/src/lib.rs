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
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(feature = "sgx")]
extern crate sgx_tstd as std;

use codec::{Decode, Encode, EncodeAppend};
use core::ops::Bound;
use derive_more::{Deref, DerefMut, From, IntoIterator};
use serde::{Deserialize, Serialize};
use sp_core::{hashing::blake2_256, H256};
use std::{collections::BTreeMap, vec, vec::Vec};

pub use scope_limited::{set_and_run_with_externalities, with_externalities};

// Unfortunately we cannot use `serde_with::serde_as` to serialize our map (which would be very convenient)
// because it has pulls in the serde and serde_json dependency with `std`, not `default-features=no`.
// Instead we use https://github.com/DenisKolodin/vectorize which is very little code, copy-pasted
// directly into this code base.
//use serde_with::serde_as;

mod codec_impl;
mod scope_limited;
// These are used to serialize a map with keys that are not string.
mod bypass;
mod vectorize;

type InternalMap<V> = BTreeMap<Vec<u8>, V>;

#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesType(#[serde(with = "vectorize")] InternalMap<Vec<u8>>);

#[derive(
	From,
	Deref,
	DerefMut,
	Clone,
	Debug,
	Default,
	PartialEq,
	Eq,
	Serialize,
	Deserialize,
	IntoIterator,
)]
pub struct SgxExternalitiesDiffType(#[serde(with = "vectorize")] InternalMap<Option<Vec<u8>>>);

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SgxExternalities {
	pub state: SgxExternalitiesType,
	pub state_diff: SgxExternalitiesDiffType,
}

pub trait StateHash {
	fn hash(&self) -> H256;
}

impl StateHash for SgxExternalities {
	fn hash(&self) -> H256 {
		self.state.using_encoded(blake2_256).into()
	}
}

pub trait SgxExternalitiesTrait {
	type SgxExternalitiesType;
	type SgxExternalitiesDiffType;

	// Create new Externaltiies with empty diff.
	fn new(state: Self::SgxExternalitiesType) -> Self;

	fn state(&self) -> &Self::SgxExternalitiesType;

	fn state_diff(&self) -> &Self::SgxExternalitiesDiffType;

	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;

	/// Append a value to an existing key.
	fn append(&mut self, k: Vec<u8>, v: Vec<u8>);

	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;

	fn get(&self, k: &[u8]) -> Option<&Vec<u8>>;

	fn contains_key(&self, k: &[u8]) -> bool;

	/// Get the next key in state after the given one (excluded) in lexicographic order.
	fn next_storage_key(&self, key: &[u8]) -> Option<Vec<u8>>;

	/// Clears all values that match the given key prefix.
	fn clear_prefix(&mut self, key_prefix: &[u8], maybe_limit: Option<u32>) -> u32;

	/// Prunes the state diff.
	fn prune_state_diff(&mut self);

	/// Execute the given closure while `self` is set as externalities.
	///
	/// Returns the result of the given closure.
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

impl SgxExternalitiesTrait for SgxExternalities
where
	SgxExternalitiesType: Encode + Decode,
	SgxExternalitiesDiffType: Encode + Decode,
{
	type SgxExternalitiesType = SgxExternalitiesType;
	type SgxExternalitiesDiffType = SgxExternalitiesDiffType;

	fn new(state: Self::SgxExternalitiesType) -> Self {
		Self { state, state_diff: Default::default() }
	}

	fn state(&self) -> &Self::SgxExternalitiesType {
		&self.state
	}

	fn state_diff(&self) -> &Self::SgxExternalitiesDiffType {
		&self.state_diff
	}

	fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) -> Option<Vec<u8>> {
		self.state_diff.insert(key.clone(), Some(value.clone()));
		self.state.insert(key, value)
	}

	fn append(&mut self, key: Vec<u8>, value: Vec<u8>) {
		let current = self.state.entry(key.clone()).or_default();
		let updated_value = StorageAppend::new(current).append(value);
		self.state_diff.insert(key, Some(updated_value));
	}

	fn remove(&mut self, key: &[u8]) -> Option<Vec<u8>> {
		self.state_diff.insert(key.to_vec(), None);
		self.state.remove(key)
	}

	fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
		self.state.get(key)
	}

	fn contains_key(&self, key: &[u8]) -> bool {
		self.state.contains_key(key)
	}

	fn next_storage_key(&self, key: &[u8]) -> Option<Vec<u8>> {
		let range = (Bound::Excluded(key), Bound::Unbounded);
		self.state.range::<[u8], _>(range).next().map(|(k, _v)| k.to_vec()) // directly return k as _v is never None in our case
	}

	fn prune_state_diff(&mut self) {
		self.state_diff.clear();
	}

	fn clear_prefix(&mut self, key_prefix: &[u8], _maybe_limit: Option<u32>) -> u32 {
		// Inspired by Substrate https://github.com/paritytech/substrate/blob/c8653447fc8ef8d95a92fe164c96dffb37919e85/primitives/state-machine/src/basic.rs#L242-L254
		let to_remove = self
			.state
			.range::<[u8], _>((Bound::Included(key_prefix), Bound::Unbounded))
			.map(|(k, _)| k)
			.take_while(|k| k.starts_with(key_prefix))
			.cloned()
			.collect::<Vec<_>>();

		let count = to_remove.len() as u32;
		for key in to_remove {
			self.remove(&key);
		}
		count
	}

	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R {
		set_and_run_with_externalities(self, f)
	}
}

/// Results concerning an operation to remove many keys.
#[derive(codec::Encode, codec::Decode)]
#[must_use]
pub struct MultiRemovalResults {
	/// A continuation cursor which, if `Some` must be provided to the subsequent removal call.
	/// If `None` then all removals are complete and no further calls are needed.
	pub maybe_cursor: Option<Vec<u8>>,
	/// The number of items removed from the backend database.
	pub backend: u32,
	/// The number of unique keys removed, taking into account both the backend and the overlay.
	pub unique: u32,
	/// The number of iterations (each requiring a storage seek/read) which were done.
	pub loops: u32,
}

impl MultiRemovalResults {
	/// Deconstruct into the internal components.
	///
	/// Returns `(maybe_cursor, backend, unique, loops)`.
	pub fn deconstruct(self) -> (Option<Vec<u8>>, u32, u32, u32) {
		(self.maybe_cursor, self.backend, self.unique, self.loops)
	}
}

/// Auxialiary structure for appending a value to a storage item.
/// Taken from https://github.com/paritytech/substrate/blob/master/primitives/state-machine/src/ext.rs
pub(crate) struct StorageAppend<'a>(&'a mut Vec<u8>);

impl<'a> StorageAppend<'a> {
	/// Create a new instance using the given `storage` reference.
	pub fn new(storage: &'a mut Vec<u8>) -> Self {
		Self(storage)
	}

	/// Append the given `value` to the storage item.
	///
	/// If appending fails, `[value]` is stored in the storage item.
	pub fn append(&mut self, value: Vec<u8>) -> Vec<u8> {
		let value = vec![EncodeOpaqueValue(value)];

		let item = core::mem::take(self.0);

		*self.0 = match Vec::<EncodeOpaqueValue>::append_or_new(item, &value) {
			Ok(item) => item,
			Err(_) => {
				log::error!("Failed to append value, resetting storage item to input value.");
				value.encode()
			},
		};
		(*self.0).to_vec()
	}
}

/// Implement `Encode` by forwarding the stored raw vec.
struct EncodeOpaqueValue(Vec<u8>);

impl Encode for EncodeOpaqueValue {
	fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
		f(&self.0)
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;

	#[test]
	fn mutating_externalities_through_environmental_variable_works() {
		let mut externalities = SgxExternalities::default();

		externalities.execute_with(|| {
			with_externalities(|e| {
				e.insert("building".encode(), "empire_state".encode());
				e.insert("house".encode(), "ginger_bread".encode());
			})
			.unwrap()
		});

		let state_len =
			externalities.execute_with(|| with_externalities(|e| e.state.0.len()).unwrap());

		assert_eq!(2, state_len);
	}

	#[test]
	fn basic_externalities_is_empty() {
		let ext = SgxExternalities::default();
		assert!(ext.state.0.is_empty());
	}

	#[test]
	fn storage_append_works() {
		let mut data = Vec::new();
		let mut append = StorageAppend::new(&mut data);
		append.append(1u32.encode());
		let updated_data = append.append(2u32.encode());
		drop(append);

		assert_eq!(Vec::<u32>::decode(&mut &data[..]).unwrap(), vec![1, 2]);
		assert_eq!(updated_data, data);

		// Initialize with some invalid data
		let mut data = vec![1];
		let mut append = StorageAppend::new(&mut data);
		append.append(1u32.encode());
		append.append(2u32.encode());
		drop(append);

		assert_eq!(Vec::<u32>::decode(&mut &data[..]).unwrap(), vec![1, 2]);
	}

	#[test]
	#[should_panic(expected = "already borrowed: BorrowMutError")]
	fn nested_with_externalities_panics() {
		let mut ext = SgxExternalities::default();

		ext.execute_with(|| {
			with_externalities(|_| with_externalities(|_| unreachable!("panics before")).unwrap())
				.unwrap();
		});
	}

	#[test]
	fn nesting_execute_with_uses_the_latest_externalities() {
		let mut ext = SgxExternalities::default();
		let mut ext2 = ext.clone();

		let hello = b"hello".to_vec();
		let world = b"world".to_vec();

		ext.execute_with(|| {
			with_externalities(|e| {
				e.insert(hello.clone(), hello.clone());
			})
			.unwrap();

			ext2.execute_with(|| {
				// `with_externalities` uses the latest set externalities defined by the last
				// `set_and_run_with_externalities` call.
				with_externalities(|e| {
					e.insert(world.clone(), world.clone());
				})
				.unwrap();
			});
		});

		assert_eq!(ext.get(&hello), Some(&hello));
		assert_eq!(ext2.get(&world), Some(&world));

		// ext1 and ext2 are unrelated.
		assert_eq!(ext.get(&world), None);
	}

	#[test]
	fn clear_prefix_works() {
		let mut externalities = SgxExternalities::default();
		let non_house_key = b"window house".to_vec();
		let non_house_value = b"test_string".to_vec();
		// Fill state.
		externalities.execute_with(|| {
			with_externalities(|e| {
				e.insert(b"house_building".to_vec(), b"empire_state".to_vec());
				e.insert(b"house".to_vec(), b"ginger_bread".to_vec());
				e.insert(b"house door".to_vec(), b"right".to_vec());
				e.insert(non_house_key.clone(), non_house_value.clone());
			})
			.unwrap()
		});
		let state_len =
			externalities.execute_with(|| with_externalities(|e| e.state.0.len()).unwrap());
		assert_eq!(state_len, 4);

		let number_of_removed_items = externalities
			.execute_with(|| with_externalities(|e| e.clear_prefix(b"house", None)).unwrap());
		assert_eq!(number_of_removed_items, 3);

		let state_len =
			externalities.execute_with(|| with_externalities(|e| e.state.0.len()).unwrap());
		assert_eq!(state_len, 1);
		let stored_value = externalities.execute_with(|| {
			with_externalities(|e| {
				assert_eq!(e.get(&non_house_key).unwrap().clone(), non_house_value)
			})
		});
		assert!(stored_value.is_some());
	}
}
