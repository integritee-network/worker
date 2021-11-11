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
	error::{Error, Result},
	utils::now_as_u64,
};
use codec::Encode;
use ita_stf::StatePayload;
use itp_settings::node::{PROPOSED_SIDECHAIN_BLOCK, TEEREX_MODULE};
use itp_sgx_crypto::StateCrypto;
use itp_stf_executor::traits::StfExecuteGenericUpdate;
use itp_types::{OpaqueCall, ShardIdentifier, H256};
use its_sidechain::{
	primitives::traits::{Block as SidechainBlockT, SignBlock, SignedBlock as SignedBlockT},
	state::{LastBlockExt, SidechainDB, SidechainState, SidechainSystemExt, StateHash},
	top_pool_rpc_author::traits::{AuthorApi, OnBlockCreated, SendState},
};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::Pair;
use sp_runtime::{
	traits::{Block as BlockT, Header},
	MultiSignature,
};
use std::{format, marker::PhantomData, sync::Arc, vec::Vec};

/// Compose a sidechain block and corresponding confirmation extrinsic for the parentchain
///
pub trait ComposeBlockAndConfirmation {
	type SidechainBlockT: SignedBlockT;
	type ParentchainBlockT: BlockT;

	fn compose_block_and_confirmation(
		&self,
		latest_onchain_header: &<Self::ParentchainBlockT as BlockT>::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
	) -> Result<(OpaqueCall, Self::SidechainBlockT)>;
}

/// Block composer implementation for the sidechain
pub struct BlockComposer<PB, SB, Signer, StateKey, RpcAuthor, StfExecutor> {
	signer: Signer,
	state_key: StateKey,
	rpc_author: Arc<RpcAuthor>,
	stf_executor: Arc<StfExecutor>,
	_phantom: PhantomData<(PB, SB)>,
}

impl<PB, SB, Signer, StateKey, RpcAuthor, StfExecutor>
	BlockComposer<PB, SB, Signer, StateKey, RpcAuthor, StfExecutor>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = Signer::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	SB::Signature: From<Signer::Signature>,
	RpcAuthor:
		AuthorApi<H256, PB::Hash> + OnBlockCreated<Hash = PB::Hash> + SendState<Hash = PB::Hash>,
	StfExecutor: StfExecuteGenericUpdate,
	<StfExecutor as StfExecuteGenericUpdate>::Externalities:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Public: Encode,
	StateKey: StateCrypto,
{
	pub fn new(
		signer: Signer,
		state_key: StateKey,
		rpc_author: Arc<RpcAuthor>,
		stf_executor: Arc<StfExecutor>,
	) -> Self {
		BlockComposer { signer, state_key, rpc_author, stf_executor, _phantom: Default::default() }
	}
}

impl<PB, SB, Signer, StateKey, RpcAuthor, StfExecutor> ComposeBlockAndConfirmation
	for BlockComposer<PB, SB, Signer, StateKey, RpcAuthor, StfExecutor>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = Signer::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	SB::Signature: From<Signer::Signature>,
	RpcAuthor:
		AuthorApi<H256, PB::Hash> + OnBlockCreated<Hash = PB::Hash> + SendState<Hash = PB::Hash>,
	StfExecutor: StfExecuteGenericUpdate,
	<StfExecutor as StfExecuteGenericUpdate>::Externalities:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
	Signer: Pair<Public = sp_core::ed25519::Public>,
	Signer::Public: Encode,
	StateKey: StateCrypto,
{
	type SidechainBlockT = SB;
	type ParentchainBlockT = PB;

	fn compose_block_and_confirmation(
		&self,
		latest_onchain_header: &PB::Header,
		top_call_hashes: Vec<H256>,
		shard: ShardIdentifier,
		state_hash_apriori: H256,
	) -> Result<(OpaqueCall, Self::SidechainBlockT)> {
		let author_public = self.signer.public();
		let (block, _) = self.stf_executor.execute_update(&shard, |state| {
			let mut db = SidechainDB::<
				SB::Block,
				<StfExecutor as StfExecuteGenericUpdate>::Externalities,
			>::new(state);
			let state_hash_new = db.state_hash();

			let (block_number, parent_hash) = match db.get_last_block() {
				Some(block) => (block.block_number() + 1, block.hash()),
				None => {
					info!("Seems to be first sidechain block.");
					(1, Default::default())
				},
			};

			if block_number != db.get_block_number().unwrap_or(0) {
				return Err(Error::Other(
					"[Sidechain] BlockNumber is not LastBlock's Number + 1".into(),
				))
			}

			// create encrypted payload
			let mut payload: Vec<u8> = StatePayload::new(
				state_hash_apriori,
				state_hash_new,
				db.ext().state_diff().clone(),
			)
			.encode();

			self.state_key.encrypt(&mut payload).map_err(|e| {
				Error::Other(format!("Failed to encrypt state payload: {:?}", e).into())
			})?;

			let block = SB::Block::new(
				author_public,
				block_number,
				parent_hash,
				latest_onchain_header.hash(),
				shard,
				top_call_hashes,
				payload,
				now_as_u64(),
			);

			db.set_last_block(&block);

			// state diff has been written to block, clean it for the next block.
			db.ext_mut().prune_state_diff();

			Ok((db.ext, block))
		})?;

		let block_hash = block.hash();
		debug!("Block hash {}", block_hash);

		let opaque_call = create_proposed_sidechain_block_call(shard, block_hash);

		self.rpc_author.on_block_created(block.signed_top_hashes(), block.hash());
		let signed_block = block.sign_block(&self.signer);

		Ok((opaque_call, signed_block))
	}
}

/// Creates a proposed_sidechain_block extrinsic for a given shard id and sidechain block hash.
fn create_proposed_sidechain_block_call(shard_id: ShardIdentifier, block_hash: H256) -> OpaqueCall {
	OpaqueCall::from_tuple(&([TEEREX_MODULE, PROPOSED_SIDECHAIN_BLOCK], shard_id, block_hash))
}
