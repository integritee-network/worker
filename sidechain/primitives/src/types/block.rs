use crate::traits::{Block as BlockT, SignedBlock as SignedBlockT};
use codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, hashing, H256};
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
	block: Block,
	/// block author signature
	signature: Signature,
}

/// simplified block structure for relay chain submission as an extrinsic
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
	block_number: BlockNumber,
	parent_hash: H256,
	timestamp: u64,
	/// hash of the last header of block in layer one
	/// needed in case extrinsics depend on layer one state
	layer_one_head: H256,
	shard_id: ShardIdentifier,
	///  must be registered on layer one as an enclave for the respective shard
	block_author: AccountId32,
	signed_top_hashes: Vec<H256>,
	// encrypted state payload
	state_payload: Vec<u8>,
}

impl BlockT for Block {
	type ShardIdentifier = H256;

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
	fn block_author(&self) -> &AccountId32 {
		&self.block_author
	}
	/// get reference of extrinisics of block
	fn signed_top_hashes(&self) -> &[H256] {
		&self.signed_top_hashes
	}
	/// get encrypted payload
	fn state_payload(&self) -> &[u8] {
		&self.state_payload
	}
	/// Constructs an unsigned block
	/// Todo: group arguments in structs.
	#[allow(clippy::too_many_arguments)]
	fn new(
		author: AccountId32,
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
	type Signature = Signature;

	fn new(block: Self::Block, signature: Self::Signature) -> Self {
		Self { block, signature }
	}
	/// get block reference
	fn block(&self) -> &Block {
		&self.block
	}
	/// get signature reference
	fn signature(&self) -> &Signature {
		&self.signature
	}
	/// get blake2_256 hash of block
	fn hash(&self) -> H256 {
		hashing::blake2_256(&mut self.block.encode().as_slice()).into()
	}
	/// Verifies the signature of a Block
	fn verify_signature(&self) -> bool {
		// get block payload
		let payload = self.block.encode();

		// verify signature
		self.signature.verify(payload.as_slice(), &self.block.block_author)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::traits::{Block as BlockT, SignBlock};
	use sp_core::{ed25519, Pair};
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
