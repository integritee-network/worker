// Todo: I think we can upstream the codec change, then we can delete this crate.

use core::num::TryFromIntError;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

// re-export the original one implementing all the merkle/logic.
pub use binary_merkle_tree::{merkle_proof, MerkleProof};

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
	pub number_of_leaves: u32,
	/// Index of the leaf the proof is for (0-based).
	pub leaf_index: u32,
	/// Leaf content.
	pub leaf: L,
}

impl<H, L> TryFrom<MerkleProof<H, L>> for MerkleProofWithCodec<H, L> {
	type Error = TryFromIntError;

	fn try_from(source: MerkleProof<H, L>) -> Result<Self, TryFromIntError> {
		Ok(Self {
			root: source.root,
			proof: source.proof,
			number_of_leaves: source.number_of_leaves.try_into()?,
			leaf_index: source.leaf_index.try_into()?,
			leaf: source.leaf,
		})
	}
}
