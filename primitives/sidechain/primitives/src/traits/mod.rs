//! Some basic abstractions used in sidechain
//!
//! Todo: This crate should be more generic and supply blanket implementations for
//! some generic structs.
//!

use codec::{Decode, Encode};
use sp_core::{crypto::AccountId32, Pair, H256};
use sp_std::prelude::*;

/// Abstraction around a sidechain block.
/// Todo: Make more generic.
pub trait Block: Encode + Decode {
	type ShardIdentifier;
	///get block number
	fn block_number(&self) -> u64;
	/// get parent hash of block
	fn parent_hash(&self) -> H256;
	/// get timestamp of block
	fn timestamp(&self) -> i64;
	/// get layer one head of block
	fn layer_one_head(&self) -> H256;
	/// get shard id of block
	fn shard_id(&self) -> Self::ShardIdentifier;
	/// get author of block
	fn block_author(&self) -> &AccountId32;
	/// get reference of extrinsics of block
	fn signed_top_hashes(&self) -> &[H256];
	/// get encrypted payload
	fn state_payload(&self) -> &[u8];
	/// create a new block instance
	/// Todo: group arguments in structs -> Header
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
	) -> Self;
}

pub trait SignedBlock {
	type Block: Block;
	type Signature;

	/// create a new block instance
	fn new(block: Self::Block, signer: Self::Signature) -> Self;

	/// get block reference
	fn block(&self) -> &Self::Block;
	/// get signature reference
	fn signature(&self) -> &Self::Signature;
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
