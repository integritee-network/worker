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

use codec::{Decode, Encode};
use derive_more::{Deref, DerefMut, From};
use environmental::environmental;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, vec::Vec};

// Unfortunately we cannot use `serde_with::serde_as` to serialize our map (which would be very convenient)
// because it has pulls in the serde and serde_json dependency with `std`, not `default-features=no`.
// Instead we use https://github.com/DenisKolodin/vectorize which is very little code, copy-pasted
// directly into this code base.
//use serde_with::serde_as;

mod codec_impl;
// These are used to serialize a map with keys that are not string.
mod bypass;
mod vectorize;

type InternalMap<V> = BTreeMap<Vec<u8>, V>;

#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesType(#[serde(with = "vectorize")] InternalMap<Vec<u8>>);

#[derive(From, Deref, DerefMut, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SgxExternalitiesDiffType(#[serde(with = "vectorize")] InternalMap<Option<Vec<u8>>>);

#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub struct SgxExternalities {
	pub state: SgxExternalitiesType,
	pub state_diff: SgxExternalitiesDiffType,
}

environmental!(ext: SgxExternalities);

pub trait SgxExternalitiesTrait {
	fn new() -> Self;
	fn state(&self) -> &SgxExternalitiesType;
	fn state_diff(&self) -> &SgxExternalitiesDiffType;
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>>;
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>>;
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>>;
	fn contains_key(&self, k: &[u8]) -> bool;
	fn prune_state_diff(&mut self);
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R;
}

impl SgxExternalitiesTrait for SgxExternalities {
	/// Create a new instance of `BasicExternalities`
	fn new() -> Self {
		Default::default()
	}

	fn state(&self) -> &SgxExternalitiesType {
		&self.state
	}

	fn state_diff(&self) -> &SgxExternalitiesDiffType {
		&self.state_diff
	}

	/// Insert key/value
	fn insert(&mut self, k: Vec<u8>, v: Vec<u8>) -> Option<Vec<u8>> {
		self.state_diff.insert(k.clone(), Some(v.clone()));
		self.state.insert(k, v)
	}

	/// remove key
	fn remove(&mut self, k: &[u8]) -> Option<Vec<u8>> {
		self.state_diff.insert(k.to_vec(), None);
		self.state.remove(k)
	}

	/// get value from state of key
	fn get(&self, k: &[u8]) -> Option<&Vec<u8>> {
		self.state.get(k)
	}

	/// check if state contains key
	fn contains_key(&self, k: &[u8]) -> bool {
		self.state.contains_key(k)
	}

	/// prunes the state diff
	fn prune_state_diff(&mut self) {
		self.state_diff.clear();
	}

	/// Execute the given closure while `self` is set as externalities.
	///
	/// Returns the result of the given closure.
	fn execute_with<R>(&mut self, f: impl FnOnce() -> R) -> R {
		set_and_run_with_externalities(self, f)
	}
}

/// Set the given externalities while executing the given closure. To get access to the externalities
/// while executing the given closure [`with_externalities`] grants access to them. The externalities
/// are only set for the same thread this function was called from.
pub fn set_and_run_with_externalities<F: FnOnce() -> R, R>(ext: &mut SgxExternalities, f: F) -> R {
	ext::using(ext, f)
}

/// Execute the given closure with the currently set externalities.
///
/// Returns `None` if no externalities are set or `Some(_)` with the result of the closure.
pub fn with_externalities<F: FnOnce(&mut SgxExternalities) -> R, R>(f: F) -> Option<R> {
	ext::with(f)
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
}
