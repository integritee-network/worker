use crate::traits::{Block as BlockT, SignedBlock as SignedBlockT};
use codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, H256};
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
	timestamp: i64,
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
	fn timestamp(&self) -> i64 {
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
		timestamp: i64,
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
	use std::{
		thread,
		time::{Duration, SystemTime, UNIX_EPOCH},
	};

	/// sets the timestamp of the block as seconds since unix epoch
	fn get_time() -> i64 {
		SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
	}

	#[test]
	fn block_new_works() {
		// given
		let author: AccountId32 =
			ed25519::Pair::from_string("//Alice", None).unwrap().public().into();
		let block_number: u64 = 0;
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];
		let shard = ShardIdentifier::default();

		// when
		let block = Block::new(
			author.clone(),
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
			get_time(),
		);

		// then
		assert_eq!(block_number, block.block_number());
		assert_eq!(parent_hash, block.parent_hash());
		assert_eq!(layer_one_head, block.layer_one_head());
		assert_eq!(shard, block.shard_id());
		assert_eq!(&author, block.block_author());
		assert_eq!(signed_top_hashes, *block.signed_top_hashes());
		assert_eq!(encrypted_payload, *block.state_payload());
	}

	#[test]
	fn signing_works() {
		// given
		let signer_pair = ed25519::Pair::from_string("//Alice", None).unwrap();
		let author: AccountId32 = signer_pair.public().into();
		let block_number: u64 = 0;
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];
		let shard = ShardIdentifier::default();

		// when
		let block = Block::new(
			author,
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
			get_time(),
		);

		let signature: Signature =
			Signature::Ed25519(signer_pair.sign(block.encode().as_slice().into()));
		let signed_block: SignedBlock = block.clone().sign_block(&signer_pair);

		// then
		assert_eq!(signed_block.block(), &block);
		assert_eq!(signed_block.signature(), &signature);
	}

	#[test]
	fn verify_signature_works() {
		// given
		let signer_pair = ed25519::Pair::from_string("//Alice", None).unwrap();
		let author: AccountId32 = signer_pair.public().into();
		let block_number: u64 = 0;
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];
		let shard = ShardIdentifier::default();

		// when
		let signed_block: SignedBlock = Block::new(
			author,
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
			get_time(),
		)
		.sign_block(&signer_pair);

		// then
		assert!(signed_block.verify_signature());
	}

	#[test]
	fn tampered_block_verify_signature_fails() {
		// given
		let signer_pair = ed25519::Pair::from_string("//Alice", None).unwrap();
		let author: AccountId32 = signer_pair.public().into();
		let block_number: u64 = 0;
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];
		let shard = ShardIdentifier::default();

		// when
		let mut signed_block: SignedBlock = Block::new(
			author,
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
			get_time(),
		)
		.sign_block(&signer_pair);
		signed_block.block.block_number = 1;

		// then
		assert_eq!(signed_block.verify_signature(), false);
	}

	#[test]
	fn get_time_works() {
		// given
		let two_seconds = Duration::new(2, 0);
		let now = get_time();
		// when
		thread::sleep(two_seconds);
		// then
		assert_eq!(now + two_seconds.as_secs() as i64, get_time());
	}

	#[test]
	fn setting_timestamp_works() {
		// given
		let signer_pair = ed25519::Pair::from_string("//Alice", None).unwrap();
		let author: AccountId32 = signer_pair.public().into();
		let block_number: u64 = 0;
		let parent_hash = H256::random();
		let layer_one_head = H256::random();
		let signed_top_hashes = vec![];
		let encrypted_payload: Vec<u8> = vec![];
		let shard = ShardIdentifier::default();

		// when
		let block = Block::new(
			author,
			block_number,
			parent_hash.clone(),
			layer_one_head.clone(),
			shard.clone(),
			signed_top_hashes.clone(),
			encrypted_payload.clone(),
			get_time(),
		);
		let one_second = Duration::new(1, 0);
		let now = block.timestamp();
		thread::sleep(one_second);

		// then
		assert_eq!(now + one_second.as_secs() as i64, get_time());
	}
}
