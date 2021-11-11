// This file is part of Substrate.

// Copyright (C) 2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// FIXME: Remove this once we reach substrate commit
/// https://github.com/paritytech/substrate/commit/65ac6f39c72e77fd98f337f1a5beddd539ee8d6f#diff-ffd4062a9fd23035055cc0ccdb7611783f3e17e55eaf25917f5482c2893ca766
/// (on 23th september) and import directly from substrate..
extern crate alloc;
use alloc::vec::Vec;

/// Supported hashing output size.
///
/// The size is restricted to 32 bytes to allow for a more optimised implementation.
pub type Hash = [u8; 32];

/// Generic hasher trait.
///
/// Implement the function to support custom way of hashing data.
/// The implementation must return a [Hash] type, so only 32-byte output hashes are supported.
pub trait Hasher {
	/// Hash given arbitrary-length piece of data.
	fn hash(data: &[u8]) -> Hash;
}

mod keccak256 {
	use tiny_keccak::{Hasher as _, Keccak};

	/// Keccak256 hasher implementation.
	pub struct Keccak256;
	impl Keccak256 {
		/// Hash given data.
		#[allow(unused)]
		pub fn hash(data: &[u8]) -> super::Hash {
			<Keccak256 as super::Hasher>::hash(data)
		}
	}
	impl super::Hasher for Keccak256 {
		fn hash(data: &[u8]) -> super::Hash {
			let mut keccak = Keccak::v256();
			keccak.update(data);
			let mut output = [0_u8; 32];
			keccak.finalize(&mut output);
			output
		}
	}
}
pub use keccak256::Keccak256;

/// Construct a root hash of a Binary Merkle Tree created from given leaves.
///
/// See crate-level docs for details about Merkle Tree construction.
///
/// In case an empty list of leaves is passed the function returns a 0-filled hash.
pub fn merkle_root<H, I, T>(leaves: I) -> Hash
where
	H: Hasher,
	I: IntoIterator<Item = T>,
	T: AsRef<[u8]>,
{
	let iter = leaves.into_iter().map(|l| H::hash(l.as_ref()));
	merkelize::<H, _, _>(iter, &mut ())
}

fn merkelize<H, V, I>(leaves: I, visitor: &mut V) -> Hash
where
	H: Hasher,
	V: Visitor,
	I: Iterator<Item = Hash>,
{
	let upper = Vec::with_capacity(leaves.size_hint().0);
	let mut next = match merkelize_row::<H, _, _>(leaves, upper, visitor) {
		Ok(root) => return root,
		Err(next) if next.is_empty() => return Hash::default(),
		Err(next) => next,
	};

	let mut upper = Vec::with_capacity((next.len() + 1) / 2);
	loop {
		visitor.move_up();

		match merkelize_row::<H, _, _>(next.drain(..), upper, visitor) {
			Ok(root) => return root,
			Err(t) => {
				// swap collections to avoid allocations
				upper = next;
				next = t;
			},
		};
	}
}

/// A generated merkle proof.
///
/// The structure contains all necessary data to later on verify the proof and the leaf itself.
#[derive(Debug, PartialEq, Eq)]
pub struct MerkleProof<T> {
	/// Root hash of generated merkle tree.
	pub root: Hash,
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<Hash>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	pub number_of_leaves: usize,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: usize,
	/// Leaf content.
	pub leaf: T,
}

/// A trait of object inspecting merkle root creation.
///
/// It can be passed to [`merkelize_row`] or [`merkelize`] functions and will be notified
/// about tree traversal.
trait Visitor {
	/// We are moving one level up in the tree.
	fn move_up(&mut self);

	/// We are creating an inner node from given `left` and `right` nodes.
	///
	/// Note that in case of last odd node in the row `right` might be empty.
	/// The method will also visit the `root` hash (level 0).
	///
	/// The `index` is an index of `left` item.
	fn visit(&mut self, index: usize, left: &Option<Hash>, right: &Option<Hash>);
}

/// No-op implementation of the visitor.
impl Visitor for () {
	fn move_up(&mut self) {}
	fn visit(&mut self, _index: usize, _left: &Option<Hash>, _right: &Option<Hash>) {}
}

/// Leaf node for proof verification.
///
/// Can be either a value that needs to be hashed first,
/// or the hash itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Leaf<'a> {
	/// Leaf content.
	Value(&'a [u8]),
	/// Hash of the leaf content.
	Hash(Hash),
}

impl<'a, T: AsRef<[u8]>> From<&'a T> for Leaf<'a> {
	fn from(v: &'a T) -> Self {
		Leaf::Value(v.as_ref())
	}
}

impl<'a> From<Hash> for Leaf<'a> {
	fn from(v: Hash) -> Self {
		Leaf::Hash(v)
	}
}

/// Processes a single row (layer) of a tree by taking pairs of elements,
/// concatenating them, hashing and placing into resulting vector.
///
/// In case only one element is provided it is returned via `Ok` result, in any other case (also an
/// empty iterator) an `Err` with the inner nodes of upper layer is returned.
fn merkelize_row<H, V, I>(
	mut iter: I,
	mut next: Vec<Hash>,
	visitor: &mut V,
) -> Result<Hash, Vec<Hash>>
where
	H: Hasher,
	V: Visitor,
	I: Iterator<Item = Hash>,
{
	#[cfg(feature = "debug")]
	log::debug!("[merkelize_row]");
	next.clear();

	let mut index = 0;
	let mut combined = [0_u8; 64];
	loop {
		let a = iter.next();
		let b = iter.next();
		visitor.visit(index, &a, &b);

		#[cfg(feature = "debug")]
		log::debug!("  {:?}\n  {:?}", a.as_ref().map(hex::encode), b.as_ref().map(hex::encode));

		index += 2;
		match (a, b) {
			(Some(a), Some(b)) => {
				combined[0..32].copy_from_slice(&a);
				combined[32..64].copy_from_slice(&b);

				next.push(H::hash(&combined));
			},
			// Odd number of items. Promote the item to the upper layer.
			(Some(a), None) if !next.is_empty() => {
				next.push(a);
			},
			// Last item = root.
			(Some(a), None) => return Ok(a),
			// Finish up, no more items.
			_ => {
				#[cfg(feature = "debug")]
				log::debug!(
					"[merkelize_row] Next: {:?}",
					next.iter().map(hex::encode).collect::<Vec<_>>()
				);
				return Err(next)
			},
		}
	}
}
