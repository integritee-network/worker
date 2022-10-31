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
//! Hashing traits and utilities.

#![cfg_attr(not(feature = "std"), no_std)]

use sp_core::H256;

#[cfg(feature = "std")]
pub mod std_hash;

/// Trait to compute a hash of self.
pub trait Hash<Output> {
	fn hash(&self) -> Output;
}

// Cannot use the implementation below unfortunately, because our externalities
// have their own hash implementation which ignores the state diff.
// /// Implement Hash<H256> for any types that implement encode.
// ///
// ///
// impl<T: Encode> Hash<H256> for T {
// 	fn hash(&self) -> H256 {
// 		blake2_256(&self.encode()).into()
// 	}
// }

pub fn hash_from_slice(hash_slize: &[u8]) -> H256 {
	let mut g = [0; 32];
	g.copy_from_slice(hash_slize);
	H256::from(&mut g)
}
