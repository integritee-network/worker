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

use crate::{BlockImport, ConfirmBlockImport, Error, Result};
use core::marker::PhantomData;
use itp_ocall_api::EnclaveSidechainOCallApi;
use itp_types::H256;
use its_primitives::{
	traits::{
		Block as BlockTrait, Header as HeaderTrait, ShardIdentifierFor,
		SignedBlock as SignedSidechainBlockTrait,
	},
	types::BlockHash,
};
use log::*;
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait};
use std::{sync::Arc, vec::Vec};

/// Trait for syncing sidechain blocks from a peer validateer.
///
/// This entails importing blocks and detecting if we're out of date with our blocks, in which
/// case we fetch the missing blocks from a peer.
pub trait SyncBlockFromPeer<ParentchainHeader, SignedSidechainBlock>
where
	ParentchainHeader: ParentchainHeaderTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	fn sync_block(
		&self,
		sidechain_block: SignedSidechainBlock,
		last_imported_parentchain_header: &ParentchainHeader,
	) -> Result<ParentchainHeader>;
}

/// Sidechain peer block sync implementation.
pub struct PeerBlockSync<
	ParentchainBlock,
	SignedSidechainBlock,
	BlockImporter,
	SidechainOCallApi,
	ImportConfirmationHandler,
> {
	importer: Arc<BlockImporter>,
	sidechain_ocall_api: Arc<SidechainOCallApi>,
	import_confirmation_handler: Arc<ImportConfirmationHandler>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<
		ParentchainBlock,
		SignedSidechainBlock,
		BlockImporter,
		SidechainOCallApi,
		ImportConfirmationHandler,
	>
	PeerBlockSync<
		ParentchainBlock,
		SignedSidechainBlock,
		BlockImporter,
		SidechainOCallApi,
		ImportConfirmationHandler,
	> where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as BlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	BlockImporter: BlockImport<ParentchainBlock, SignedSidechainBlock>,
	SidechainOCallApi: EnclaveSidechainOCallApi,
	ImportConfirmationHandler: ConfirmBlockImport<
		<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as BlockTrait>::HeaderType,
	>,
{
	pub fn new(
		importer: Arc<BlockImporter>,
		sidechain_ocall_api: Arc<SidechainOCallApi>,
		import_confirmation_handler: Arc<ImportConfirmationHandler>,
	) -> Self {
		PeerBlockSync {
			importer,
			sidechain_ocall_api,
			import_confirmation_handler,
			_phantom: Default::default(),
		}
	}

	fn fetch_and_import_blocks_from_peer(
		&self,
		last_imported_sidechain_block_hash: BlockHash,
		import_until_block_hash: BlockHash,
		current_parentchain_header: &ParentchainBlock::Header,
		shard_identifier: ShardIdentifierFor<SignedSidechainBlock>,
	) -> Result<ParentchainBlock::Header> {
		info!(
			"Initiating fetch blocks from peer, last imported block hash: {:?}, until block hash: {:?}",
			last_imported_sidechain_block_hash, import_until_block_hash
		);

		let blocks_to_import: Vec<SignedSidechainBlock> =
			self.sidechain_ocall_api.fetch_sidechain_blocks_from_peer(
				last_imported_sidechain_block_hash,
				Some(import_until_block_hash),
				shard_identifier,
			)?;

		info!("Fetched {} blocks from peer to import", blocks_to_import.len());

		let mut latest_imported_parentchain_header = current_parentchain_header.clone();

		for block_to_import in blocks_to_import {
			let block_number = block_to_import.block().header().block_number();

			latest_imported_parentchain_header = match self
				.importer
				.import_block(block_to_import, &latest_imported_parentchain_header)
			{
				Err(e) => {
					error!("Failed to import sidechain block that was fetched from peer: {:?}", e);
					return Err(e)
				},
				Ok(h) => {
					info!(
						"Successfully imported peer fetched sidechain block (number: {})",
						block_number
					);
					h
				},
			};
		}

		Ok(latest_imported_parentchain_header)
	}
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImporter, SidechainOCallApi, ImportConfirmationHandler>
	SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>
	for PeerBlockSync<ParentchainBlock, SignedSidechainBlock, BlockImporter, SidechainOCallApi, ImportConfirmationHandler>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	<<SignedSidechainBlock as its_primitives::traits::SignedBlock>::Block as BlockTrait>::HeaderType:
	HeaderTrait<ShardIdentifier = H256>,
	BlockImporter: BlockImport<ParentchainBlock, SignedSidechainBlock>,
	SidechainOCallApi: EnclaveSidechainOCallApi,
	ImportConfirmationHandler: ConfirmBlockImport<<<SignedSidechainBlock as SignedSidechainBlockTrait>::Block as BlockTrait>::HeaderType>,
{
	fn sync_block(
		&self,
		sidechain_block: SignedSidechainBlock,
		current_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header> {
		let shard_identifier = sidechain_block.block().header().shard_id();
		let sidechain_block_number = sidechain_block.block().header().block_number();
		let sidechain_block_hash = sidechain_block.hash();

		// Attempt to import the block - in case we encounter an ancestry error, we go into
		// peer fetching mode to fetch sidechain blocks from a peer and import those first.
		match self.importer.import_block(sidechain_block.clone(), current_parentchain_header) {
			Err(e) => match e {
				Error::BlockAncestryMismatch(_block_number, block_hash, _) => {
					warn!("Got ancestry mismatch error upon block import. Attempting to fetch missing blocks from peer");
					let updated_parentchain_header = self.fetch_and_import_blocks_from_peer(
						block_hash,
						sidechain_block_hash,
						current_parentchain_header,
						shard_identifier,
					)?;

					self.importer.import_block(sidechain_block, &updated_parentchain_header)
				},
				Error::InvalidFirstBlock(block_number, _) => {
					warn!("Got invalid first block error upon block import (expected first block, but got block with number {}). \
							Attempting to fetch missing blocks from peer", block_number);
					let updated_parentchain_header = self.fetch_and_import_blocks_from_peer(
						Default::default(), // This is the parent hash of the first block. So we import everything.
						sidechain_block_hash,
						current_parentchain_header,
						shard_identifier,
					)?;

					self.importer.import_block(sidechain_block, &updated_parentchain_header)
				},
				Error::BlockAlreadyImported(to_import_block_number, last_known_block_number) => {
					warn!("Sidechain block from queue (number: {}) was already imported (current block number: {}). Block will be ignored.", 
						to_import_block_number, last_known_block_number);
					Ok(current_parentchain_header.clone())
				},
				_ => Err(e),
			},
			Ok(latest_parentchain_header) => {
				info!("Successfully imported broadcast sidechain block (number: {}), based on parentchain block {:?}", 
					sidechain_block_number, latest_parentchain_header.number());

				// We confirm the successful block import. Only in this case, not when we're in
				// on-boarding and importing blocks that were fetched from a peer.
				if let Err(e) = self.import_confirmation_handler.confirm_import(sidechain_block.block().header(), &shard_identifier) {
					error!("Failed to confirm sidechain block import: {:?}", e);
				}

				Ok(latest_parentchain_header)
			},
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test::mocks::{
		block_importer_mock::BlockImportMock, confirm_block_import_mock::ConfirmBlockImportMock,
	};
	use core::assert_matches::assert_matches;
	use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
	use itp_test::mock::sidechain_ocall_api_mock::SidechainOCallApiMock;
	use itp_types::Block as ParentchainBlock;
	use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
	use its_test::sidechain_block_builder::{SidechainBlockBuilder, SidechainBlockBuilderTrait};

	type TestBlockImport = BlockImportMock<ParentchainBlock, SignedSidechainBlock>;
	type TestOCallApi = SidechainOCallApiMock<SignedSidechainBlock>;
	type TestPeerBlockSync = PeerBlockSync<
		ParentchainBlock,
		SignedSidechainBlock,
		TestBlockImport,
		TestOCallApi,
		ConfirmBlockImportMock,
	>;

	#[test]
	fn if_block_import_is_successful_no_peer_fetching_happens() {
		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		let block_importer_mock = Arc::new(
			BlockImportMock::<ParentchainBlock, _>::default()
				.with_import_result_once(Ok(parentchain_header.clone())),
		);

		let sidechain_ocall_api =
			Arc::new(SidechainOCallApiMock::<SignedSidechainBlock>::default());

		let peer_syncer =
			create_peer_syncer(block_importer_mock.clone(), sidechain_ocall_api.clone());

		peer_syncer.sync_block(signed_sidechain_block, &parentchain_header).unwrap();

		assert_eq!(1, block_importer_mock.get_imported_blocks().len());
		assert_eq!(0, sidechain_ocall_api.number_of_fetch_calls());
	}

	#[test]
	fn error_is_propagated_if_import_returns_error_other_than_ancestry_mismatch() {
		let block_importer_mock = Arc::new(
			BlockImportMock::<ParentchainBlock, _>::default()
				.with_import_result_once(Err(Error::InvalidAuthority("auth".to_string()))),
		);

		let sidechain_ocall_api =
			Arc::new(SidechainOCallApiMock::<SignedSidechainBlock>::default());

		let peer_syncer =
			create_peer_syncer(block_importer_mock.clone(), sidechain_ocall_api.clone());

		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		let sync_result = peer_syncer.sync_block(signed_sidechain_block, &parentchain_header);

		assert_matches!(sync_result, Err(Error::InvalidAuthority(_)));
		assert_eq!(1, block_importer_mock.get_imported_blocks().len());
		assert_eq!(0, sidechain_ocall_api.number_of_fetch_calls());
	}

	#[test]
	fn blocks_are_fetched_from_peer_if_initial_import_yields_ancestry_mismatch() {
		let block_importer_mock =
			Arc::new(BlockImportMock::<ParentchainBlock, _>::default().with_import_result_once(
				Err(Error::BlockAncestryMismatch(1, H256::random(), "".to_string())),
			));

		let sidechain_ocall_api = Arc::new(
			SidechainOCallApiMock::<SignedSidechainBlock>::default().with_peer_fetch_blocks(vec![
				SidechainBlockBuilder::random().build_signed(),
				SidechainBlockBuilder::random().build_signed(),
			]),
		);

		let peer_syncer =
			create_peer_syncer(block_importer_mock.clone(), sidechain_ocall_api.clone());

		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		peer_syncer.sync_block(signed_sidechain_block, &parentchain_header).unwrap();

		assert_eq!(4, block_importer_mock.get_imported_blocks().len());
		assert_eq!(1, sidechain_ocall_api.number_of_fetch_calls());
	}

	fn create_peer_syncer(
		block_importer: Arc<TestBlockImport>,
		ocall_api: Arc<TestOCallApi>,
	) -> TestPeerBlockSync {
		let import_confirmation_handler = Arc::new(ConfirmBlockImportMock {});
		TestPeerBlockSync::new(block_importer, ocall_api, import_confirmation_handler)
	}
}
