//! Some basic abstractions used in sidechain
//!
//! Todo: This crate should be more generic and supply blanket implementations for
//! some generic structs.
//!

use codec::{Decode, Encode};
use core::hash::Hash;
use sp_core::{blake2_256, Pair, Public, H256};
use sp_runtime::traits::Member;
use sp_std::prelude::*;

/// Abstraction around a sidechain block.
/// Todo: Make more generic.
pub trait Block: Encode + Decode + Send + Sync {
	/// Identifier for the shards
	type ShardIdentifier: Encode + Decode + Hash + Copy + Member;

	/// Public key type of the block author
	type Public: Public;

	/// get the block number
	fn block_number(&self) -> u64;
	/// get parent hash of block
	fn parent_hash(&self) -> H256;
	/// get timestamp of block
	fn timestamp(&self) -> u64;
	/// get layer one head of block
	fn layer_one_head(&self) -> H256;
	/// get shard id of block
	fn shard_id(&self) -> Self::ShardIdentifier;
	/// get author of block
	fn block_author(&self) -> &Self::Public;
	/// get reference of extrinsics of block
	fn signed_top_hashes(&self) -> &[H256];
	/// get encrypted payload
	fn state_payload(&self) -> &[u8];
	/// create a new block instance
	fn hash(&self) -> H256 {
		self.using_encoded(blake2_256).into()
	}
	/// Todo: group arguments in structs -> Header
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
	) -> Self;
}

/// ShardIdentifier for a [`SignedBlock`]
pub type ShardIdentifierFor<SB> = <<SB as SignedBlock>::Block as Block>::ShardIdentifier;

/// A block and it's corresponding signature by the [`Block`] author.
pub trait SignedBlock: Encode + Decode + Send + Sync {
	/// The block type of the signed block
	type Block: Block<Public = Self::Public>;

	/// Public key type of the signer and the block author
	type Public: Public;

	/// Signature type of the [`SignedBlock`]'s signature
	type Signature;

	/// create a new block instance
	fn new(block: Self::Block, signer: Self::Signature) -> Self;

	/// get block reference
	fn block(&self) -> &Self::Block;

	/// get signature reference
	fn signature(&self) -> &Self::Signature;

	/// get blake2_256 hash of block
	fn hash(&self) -> H256 {
		self.block().hash()
	}

	/// Verifies the signature of a Block
	fn verify_signature(&self) -> bool;
}

/// Provide signing logic blanket implementations for all block types satisfying the trait bounds.
pub trait SignBlock<B: Block, SB: SignedBlock<Block = B>> {
	fn sign_block<P: Pair>(self, signer: &P) -> SB
	where
		<SB as SignedBlock>::Signature: From<<P as sp_core::Pair>::Signature>;
}

impl<B, SB> SignBlock<B, SB> for B
where
	B: Block,
	SB: SignedBlock<Block = B>,
{
	fn sign_block<P: Pair>(self, signer: &P) -> SB
	where
		<SB as SignedBlock>::Signature: From<<P as sp_core::Pair>::Signature>,
	{
		let signature = self.using_encoded(|b| signer.sign(b)).into();
		SB::new(self, signature)
	}
}
