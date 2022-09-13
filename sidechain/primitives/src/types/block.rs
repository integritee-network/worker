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

use crate::{
	traits::{Block as BlockTrait, SignedBlock as SignedBlockTrait},
	types::{block_data::BlockData, header::SidechainHeader as Header},
};
use codec::{Decode, Encode};
use sp_core::{ed25519, H256};
use sp_runtime::{traits::Verify, MultiSignature};

pub type BlockHash = H256;
pub type BlockNumber = u64;
pub type ShardIdentifier = H256;
pub type Timestamp = u64;

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
	/// Plain sidechain block without author signature.
	pub block: Block,
	/// Block author signature.
	pub signature: Signature,
}

/// Simplified block structure for relay chain submission as an extrinsic.
#[derive(PartialEq, Eq, Clone, Encode, Decode, Debug)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub struct Block {
	/// Sidechain Header
	pub header: Header,

	/// Sidechain Block data
	pub block_data: BlockData,
}

impl BlockTrait for Block {
	type HeaderType = Header;

	type BlockDataType = BlockData;

	type Public = ed25519::Public;

	fn header(&self) -> &Self::HeaderType {
		&self.header
	}

	fn block_data(&self) -> &Self::BlockDataType {
		&self.block_data
	}

	fn new(header: Self::HeaderType, block_data: Self::BlockDataType) -> Self {
		Self { header, block_data }
	}
}

impl SignedBlockTrait for SignedBlock {
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
		self.block.using_encoded(|p| {
			self.signature.verify(p, &self.block.block_data().block_author.into())
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::traits::{Block as BlockT, BlockData, Header, SignBlock};
	use sp_core::Pair;
	use std::time::{SystemTime, UNIX_EPOCH};

	/// gets the timestamp of the block as seconds since unix epoch
	fn timestamp_now() -> Timestamp {
		SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as Timestamp
	}

	fn test_block() -> Block {
		let header = Header::new(0, H256::random(), H256::random(), Default::default());
		let block_data = BlockData::new(
			ed25519::Pair::from_string("//Alice", None).unwrap().public().into(),
			H256::random(),
			Default::default(),
			Default::default(),
			timestamp_now(),
		);

		Block::new(header, block_data)
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
		signed_block.block.header.block_number = 1;

		assert!(!signed_block.verify_signature());
	}
}
