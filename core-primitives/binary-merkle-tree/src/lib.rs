// Todo: I think we can upstream the codec change, then we can delete this crate.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// re-export the original one implementing all the merkle/logic.
pub use binary_merkle_tree::{merkle_proof, merkle_root, verify_proof, MerkleProof};

/// Custom Merkle proof that implements codec
/// The difference to the original one is that implements the scale-codec and that the fields contain u32 instead of usize.
#[derive(Debug, PartialEq, Eq, Decode, Encode, Deserialize, Serialize)]
pub struct MerkleProofWithCodec<H, L> {
	/// Root hash of generated merkle tree.
	pub root: H,
	/// Proof items (does not contain the leaf hash, nor the root obviously).
	///
	/// This vec contains all inner node hashes necessary to reconstruct the root hash given the
	/// leaf hash.
	pub proof: Vec<H>,
	/// Number of leaves in the original tree.
	///
	/// This is needed to detect a case where we have an odd number of leaves that "get promoted"
	/// to upper layers.
	pub number_of_leaves: u64,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: u64,
	/// Leaf content.
	pub leaf: L,
}

impl<H, L> From<MerkleProof<H, L>> for MerkleProofWithCodec<H, L> {
	fn from(source: MerkleProof<H, L>) -> Self {
		Self {
			root: source.root,
			proof: source.proof,
			// usize as u64 can't panic
			number_of_leaves: source.number_of_leaves as u64,
			leaf_index: source.leaf_index as u64,
			leaf: source.leaf,
		}
	}
}
