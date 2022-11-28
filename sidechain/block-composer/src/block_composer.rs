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
use itp_settings::worker::BLOCK_NUMBER_FINALIZATION_DIFF;
use itp_sgx_crypto::{key_repository::AccessKey, StateCrypto};
use itp_sgx_externalities::{SgxExternalitiesTrait, StateHash};
use itp_time_utils::now_as_millis;
use itp_types::{ShardIdentifier, H256};
use its_primitives::traits::{
	Block as SidechainBlockTrait, BlockData, Header as HeaderTrait, SignBlock,
	SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{LastBlockExt, SidechainState, SidechainSystemExt};
use log::*;
use sp_core::Pair;
use sp_runtime::{
	traits::{Block as ParentchainBlockTrait, Header},
	MultiSignature,
};
use std::{format, marker::PhantomData, sync::Arc, vec::Vec};

/// Compose a sidechain block and corresponding confirmation extrinsic for the parentchain
///
pub trait ComposeBlock<Externalities, ParentchainBlock: ParentchainBlockTrait> {
	type SignedSidechainBlock: SignedSidechainBlockTrait;

	fn compose_block(
		&self,
		latest_parentchain_header: &<ParentchainBlock as ParentchainBlockTrait>::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
		aposteriori_state: &Externalities,
	) -> Result<Self::SignedSidechainBlock>;
}

/// Block composer implementation for the sidechain
pub struct BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKeyRepository> {
	signer: Signer,
	state_key_repository: Arc<StateKeyRepository>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock, Signer, StateKeyRepository>
	BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKeyRepository>
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
	StateKeyRepository: AccessKey,
	<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
{
	pub fn new(signer: Signer, state_key_repository: Arc<StateKeyRepository>) -> Self {
		BlockComposer { signer, state_key_repository, _phantom: Default::default() }
	}
}

type HeaderTypeOf<T> = <<T as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType;
type BlockDataTypeOf<T> =
	<<T as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::BlockDataType;

impl<ParentchainBlock, SignedSidechainBlock, Signer, StateKeyRepository, Externalities>
	ComposeBlock<Externalities, ParentchainBlock>
	for BlockComposer<ParentchainBlock, SignedSidechainBlock, Signer, StateKeyRepository>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = Signer::Public, Signature = MultiSignature>,
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = sp_core::ed25519::Public>,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	SignedSidechainBlock::Signature: From<Signer::Signature>,
	Externalities: SgxExternalitiesTrait
		+ SidechainState
		+ SidechainSystemExt
		+ StateHash
		+ LastBlockExt<SignedSidechainBlock::Block>
		+ Encode,
	<Externalities as SgxExternalitiesTrait>::SgxExternalitiesType: Encode,
	<Externalities as SgxExternalitiesTrait>::SgxExternalitiesDiffType: Encode,
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Public: Encode,
	StateKeyRepository: AccessKey,
	<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
{
	type SignedSidechainBlock = SignedSidechainBlock;

	fn compose_block(
		&self,
		latest_parentchain_header: &ParentchainBlock::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
		aposteriori_state: &Externalities,
	) -> Result<Self::SignedSidechainBlock> {
		let author_public = self.signer.public();

		let state_hash_new = aposteriori_state.hash();

		let (block_number, parent_hash, next_finalization_block_number) =
			match aposteriori_state.get_last_block() {
				Some(block) => (
					block.header().block_number() + 1,
					block.hash(),
					block.header().next_finalization_block_number(),
				),
				None => {
					info!("Seems to be first sidechain block.");
					(1, Default::default(), 1)
				},
			};

		if block_number != aposteriori_state.get_block_number().unwrap_or(0) {
			return Err(Error::Other("[Sidechain] BlockNumber is not LastBlock's Number + 1".into()))
		}

		// create encrypted payload
		let mut payload: Vec<u8> =
			StatePayload::new(state_hash_apriori, state_hash_new, aposteriori_state.state_diff())
				.encode();

		let state_key = self
			.state_key_repository
			.retrieve_key()
			.map_err(|e| Error::Other(format!("Failed to retrieve state key: {:?}", e).into()))?;

		state_key.encrypt(&mut payload).map_err(|e| {
			Error::Other(format!("Failed to encrypt state payload: {:?}", e).into())
		})?;

		let block_data = BlockDataTypeOf::<SignedSidechainBlock>::new(
			author_public,
			latest_parentchain_header.hash(),
			top_call_hashes,
			payload,
			now_as_millis(),
		);

		let mut finalization_candidate = next_finalization_block_number;
		if block_number == 1 {
			finalization_candidate = 1;
		} else if block_number > finalization_candidate {
			finalization_candidate += BLOCK_NUMBER_FINALIZATION_DIFF;
		}

		let header = HeaderTypeOf::<SignedSidechainBlock>::new(
			block_number,
			parent_hash,
			shard,
			block_data.hash(),
			finalization_candidate,
		);

		let block = SignedSidechainBlock::Block::new(header.clone(), block_data);

		debug!("Block header hash {}", header.hash());

		let signed_block = block.sign_block(&self.signer);

		Ok(signed_block)
	}
}
