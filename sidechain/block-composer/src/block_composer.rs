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

use crate::error::{Error, Result};
use codec::Encode;
use ita_stf::StatePayload;
use itp_settings::node::{PROPOSED_SIDECHAIN_BLOCK, TEEREX_MODULE};
use itp_sgx_crypto::StateCrypto;
use itp_time_utils::now_as_u64;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use its_primitives::traits::{
	Block as SidechainBlockTrait, Header as HeaderTrait, SignBlock,
	SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{LastBlockExt, SidechainDB, SidechainState, SidechainSystemExt, StateHash};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::{ed25519, Pair};
use sp_runtime::{
	traits::{BlakeTwo256, Block as ParentchainBlockTrait, Hash, Header},
	MultiSignature,
};
use std::{format, marker::PhantomData, vec::Vec};

/// Compose a sidechain block and corresponding confirmation extrinsic for the parentchain
///
pub trait ComposeBlockAndConfirmation<Externalities, ParentchainBlock: ParentchainBlockTrait> {
	type SignedSidechainBlock: SignedSidechainBlockTrait;

	fn compose_block_and_confirmation(
		&self,
		latest_parentchain_header: &<ParentchainBlock as ParentchainBlockTrait>::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
		aposteriori_state: Externalities,
	) -> Result<(OpaqueCall, Self::SignedSidechainBlock)>;
}

/// Block composer implementation for the sidechain
pub struct BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKey> {
	signer: Signer,
	state_key: StateKey,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock, Signer, StateKey>
	BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKey>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = Signer::Public, Signature = MultiSignature>,
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = sp_core::ed25519::Public>,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	SignedSidechainBlock::Signature: From<Signer::Signature>,
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Public: Encode,
	StateKey: StateCrypto,
{
	pub fn new(signer: Signer, state_key: StateKey) -> Self {
		BlockComposer { signer, state_key, _phantom: Default::default() }
	}
}

impl<ParentchainBlock, SignedSidechainBlock, Signer, StateKey, Externalities>
	ComposeBlockAndConfirmation<Externalities, ParentchainBlock>
	for BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKey>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = Signer::Public, Signature = MultiSignature>,
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = sp_core::ed25519::Public>,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	SignedSidechainBlock::Signature: From<Signer::Signature>,
	Externalities: SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash + Encode,
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Public: Encode,
	StateKey: StateCrypto,
{
	type SignedSidechainBlock = SignedSidechainBlock;

	fn compose_block_and_confirmation(
		&self,
		latest_parentchain_header: &ParentchainBlock::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
		aposteriori_state: Externalities,
	) -> Result<(OpaqueCall, Self::SignedSidechainBlock)> {
		let author_public = self.signer.public();

		let db = SidechainDB::<SignedSidechainBlock::Block, Externalities>::new(aposteriori_state);
		let state_hash_new = db.state_hash();

		let (block_number, parent_hash) = match db.get_last_block() {
			Some(block) => (block.header().block_number() + 1, block.hash()),
			None => {
				info!("Seems to be first sidechain block.");
				(1, Default::default())
			},
		};

		if block_number != db.get_block_number().unwrap_or(0) {
			return Err(Error::Other("[Sidechain] BlockNumber is not LastBlock's Number + 1".into()))
		}

		// create encrypted payload
		let mut payload: Vec<u8> =
			StatePayload::new(state_hash_apriori, state_hash_new, db.ext().state_diff().clone())
				.encode();

		self.state_key.encrypt(&mut payload).map_err(|e| {
			Error::Other(format!("Failed to encrypt state payload: {:?}", e).into())
		})?;

		let now = now_as_u64();
		let layer_one_hash = latest_parentchain_header.hash();
		let payload_hash = calculate_payload_hash(
			now,
			layer_one_hash,
			author_public,
			top_call_hashes.clone(),
			payload.clone(),
		);

		let header =
			<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType::new(
				block_number,
				parent_hash,
				shard,
				payload_hash,
			);

		let block = SignedSidechainBlock::Block::new(
			header,
			author_public,
			layer_one_hash,
			top_call_hashes,
			payload,
			now,
		);

		let block_hash = block.hash();
		debug!("Block hash {}", block_hash);

		let opaque_call = create_proposed_sidechain_block_call(shard, block_hash);

		let signed_block = block.sign_block(&self.signer);

		Ok((opaque_call, signed_block))
	}
}

/// Creates a proposed_sidechain_block extrinsic for a given shard id and sidechain block hash.
fn create_proposed_sidechain_block_call(shard_id: ShardIdentifier, block_hash: H256) -> OpaqueCall {
	OpaqueCall::from_tuple(&([TEEREX_MODULE, PROPOSED_SIDECHAIN_BLOCK], shard_id, block_hash))
}

/// Calculate the payload of a sidechain block.
fn calculate_payload_hash(
	timestamp: u64,
	layer_one_head: H256,
	block_author: ed25519::Public,
	signed_top_hashes: Vec<H256>,
	state_payload: Vec<u8>,
) -> H256 {
	(timestamp, layer_one_head, block_author, signed_top_hashes, state_payload)
		.using_encoded(BlakeTwo256::hash)
}
