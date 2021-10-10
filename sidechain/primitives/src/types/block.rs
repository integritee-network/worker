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

use crate::traits::{Block as BlockT, SignedBlock as SignedBlockT};
use codec::{Decode, Encode};
use sp_core::{ed25519, H256};
use sp_runtime::{traits::Verify, MultiSignature};
use sp_std::vec::Vec;

pub type BlockHash = H256;
pub type BlockNumber = u64;
pub type ShardIdentifier = H256;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

//FIXME: Should use blocknumber from sgxruntime
// Problem: sgxruntime only with sgx, no std enviornment
// but block.rs should be available in std?
//use sgx_runtime::BlockNumber;

pub type Signature = MultiSignature;

/// signed version of block to verify block origin
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct SignedBlock {
	pub block: Block,
	/// block author signature
	pub signature: Signature,
}

/// simplified block structure for relay chain submission as an extrinsic
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
	pub block_number: BlockNumber,
	pub parent_hash: H256,
	pub timestamp: u64,
	/// Parentchain header this block is based on
	pub layer_one_head: H256,
	pub shard_id: ShardIdentifier,
	///  must be registered on layer one as an enclave for the respective shard
	pub block_author: ed25519::Public,
	pub signed_top_hashes: Vec<H256>,
	// encrypted state payload
	pub state_payload: Vec<u8>,
}

impl BlockT for Block {
	type ShardIdentifier = H256;

	type Public = ed25519::Public;

	///get block number
	fn block_number(&self) -> BlockNumber {
		self.block_number
	}
	/// get parent hash of block
	fn parent_hash(&self) -> H256 {
		self.parent_hash
	}
	/// get timestamp of block
	fn timestamp(&self) -> u64 {
		self.timestamp
	}
	/// get layer one head of block
	fn layer_one_head(&self) -> H256 {
		self.layer_one_head
	}
	/// get shard id of block
	fn shard_id(&self) -> Self::ShardIdentifier {
		self.shard_id
	}
	/// get author of block
	fn block_author(&self) -> &Self::Public {
		&self.block_author
	}
	/// get reference of extrinisics of block
	fn signed_top_hashes(&self) -> &[H256] {
		&self.signed_top_hashes
	}
	/// get encrypted payload
	fn state_payload(&self) -> &Vec<u8> {
		&self.state_payload
	}
	/// Constructs an unsigned block
	/// Todo: group arguments in structs.
	#[allow(clippy::too_many_arguments)]
	fn new(
		author: Self::Public,
		block_number: u64,
		parent_hash: H256,
		layer_one_head: H256,
		shard: Self::ShardIdentifier,
		signed_top_hashes: Vec<H256>,
		encrypted_payload: Vec<u8>,
		timestamp: u64,
	) -> Block {
		// create block
		Block {
			block_number,
			parent_hash,
			timestamp,
			layer_one_head,
			signed_top_hashes,
			shard_id: shard,
			block_author: author,
			state_payload: encrypted_payload,
		}
	}
}

impl SignedBlockT for SignedBlock {
	type Block = Block;

	type Public = ed25519::Public;

	type Signature = Signature;

	fn new(block: Self::Block, signature: Self::Signature) -> Self {
		Self { block, signature }
	}

	/// get block reference
	fn block(&self) -> &Self::Block {
		&self.block
	}

	/// get signature reference
	fn signature(&self) -> &Signature {
		&self.signature
	}

	/// Verifies the signature of a Block
	fn verify_signature(&self) -> bool {
		self.block
			.using_encoded(|p| self.signature.verify(p, &self.block.block_author.into()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::traits::{Block as BlockT, SignBlock};
	use sp_core::Pair;
	use std::time::{SystemTime, UNIX_EPOCH};

	/// gets the timestamp of the block as seconds since unix epoch
	fn timestamp_now() -> u64 {
		SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
	}

	fn test_block() -> Block {
		Block::new(
			ed25519::Pair::from_string("//Alice", None).unwrap().public().into(),
			0,
			H256::random(),
			H256::random(),
			H256::random(),
			Default::default(),
			Default::default(),
			timestamp_now(),
		)
	}

	#[test]
	fn signing_works() {
		let block = test_block();
		let signer = ed25519::Pair::from_string("//Alice", None).unwrap();

		let signature: Signature =
			Signature::Ed25519(signer.sign(block.encode().as_slice().into()));
		let signed_block: SignedBlock = block.clone().sign_block(&signer);

		assert_eq!(signed_block.block(), &block);
		assert_eq!(signed_block.signature(), &signature);
		assert!(signed_block.verify_signature());
	}

	#[test]
	fn tampered_block_verify_signature_fails() {
		let signer = ed25519::Pair::from_string("//Alice", None).unwrap();

		let mut signed_block: SignedBlock = test_block().sign_block(&signer);
		signed_block.block.block_number = 1;

		assert!(!signed_block.verify_signature());
	}
}
