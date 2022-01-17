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
	block_production_suspension::{IsBlockProductionSuspended, SuspendBlockProduction},
	BlockImport, Error, Result,
};
use core::marker::PhantomData;
use its_primitives::{traits::SignedBlock as SignedSidechainBlockTrait, types::BlockHash};
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
	) -> Result<()>;
}

/// Sidechain peer block sync implementation.
pub struct PeerBlockSync<
	ParentchainBlock,
	SignedSidechainBlock,
	BlockImporter,
	BlockProductionSuspender,
> {
	importer: Arc<BlockImporter>,
	block_production_suspender: Arc<BlockProductionSuspender>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImporter, BlockProductionSuspender>
	PeerBlockSync<ParentchainBlock, SignedSidechainBlock, BlockImporter, BlockProductionSuspender>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	BlockImporter: BlockImport<ParentchainBlock, SignedSidechainBlock>,
	BlockProductionSuspender: SuspendBlockProduction + IsBlockProductionSuspended,
{
	pub fn new(
		importer: Arc<BlockImporter>,
		block_production_suspender: Arc<BlockProductionSuspender>,
	) -> Self {
		PeerBlockSync { importer, block_production_suspender, _phantom: Default::default() }
	}

	fn fetch_and_import_blocks_from_peer(
		&self,
		_last_known_block_hash: BlockHash,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<()> {
		// TODO fetch blocks from peer

		let blocks_to_import: Vec<SignedSidechainBlock> = Vec::new();
		for block_to_import in blocks_to_import {
			self.importer.import_block(block_to_import, last_imported_parentchain_header)?;
		}

		Ok(())
	}
}

impl<ParentchainBlock, SignedSidechainBlock, BlockImporter, BlockProductionSuspender>
	SyncBlockFromPeer<ParentchainBlock::Header, SignedSidechainBlock>
	for PeerBlockSync<ParentchainBlock, SignedSidechainBlock, BlockImporter, BlockProductionSuspender>
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
	BlockImporter: BlockImport<ParentchainBlock, SignedSidechainBlock>,
	BlockProductionSuspender: SuspendBlockProduction + IsBlockProductionSuspended,
{
	fn sync_block(
		&self,
		sidechain_block: SignedSidechainBlock,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<()> {
		// In case block production is suspended, we don't import any blocks.
		// In the future we might want to cache the blocks here, so they can be imported later.
		if self.block_production_suspender.is_suspended().unwrap_or_default() {
			warn!("Sidechain block won't be imported, since block production is suspended");
			return Ok(())
		}

		// Attempt to import the block - in case we encounter an ancestry error, we go into
		// peer fetching mode to fetch sidechain blocks from a peer and import those first.
		match self.importer.import_block(sidechain_block, last_imported_parentchain_header) {
			Err(e) => match e {
				Error::BlockAncestryMismatch(_block_number, block_hash, _) => {
					warn!("Got ancestry mismatch error upon block import. Attempting to fetch missing blocks from peer");

					// Suspend block production while we sync blocks from peer.
					self.block_production_suspender.suspend()?;

					// TODO need a 'finally' (or on-drop) here for the production suspension,
					// to ensure we resume block production when we return early between `suspend` and `resume`
					// (e.g. with a `?` operator in between).

					if let Err(e) = self.fetch_and_import_blocks_from_peer(
						block_hash,
						last_imported_parentchain_header,
					) {
						// We just log the error for now. In the future we might have a way to handle this error.
						error!("Error while importing a block in the peer fetch process: {:?}", e);
					}

					self.block_production_suspender.resume()?;

					Ok(())
				},
				_ => Err(e),
			},
			Ok(()) => Ok(()),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{
		block_production_suspension::BlockProductionSuspender,
		test::mocks::block_importer_mock::BlockImportMock,
	};
	use core::assert_matches::assert_matches;
	use itp_test::builders::parentchain_header_builder::ParentchainHeaderBuilder;
	use itp_types::Block as ParentchainBlock;
	use its_test::sidechain_block_builder::SidechainBlockBuilder;

	#[test]
	fn if_block_production_is_suspended_no_block_is_imported() {
		let block_importer_mock = Arc::new(BlockImportMock::<ParentchainBlock, _>::default());
		let block_import_suspender = Arc::new(BlockProductionSuspender::default());

		let peer_syncer =
			PeerBlockSync::new(block_importer_mock.clone(), block_import_suspender.clone());

		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		block_import_suspender.suspend().unwrap();

		peer_syncer.sync_block(signed_sidechain_block, &parentchain_header).unwrap();

		assert!(block_import_suspender.is_suspended().unwrap());
		assert!(block_importer_mock.get_imported_blocks().is_empty());
	}

	#[test]
	fn if_block_import_is_successful_no_peer_fetching_happens() {
		let block_importer_mock =
			Arc::new(BlockImportMock::<ParentchainBlock, _>::default().with_import_result(Ok(())));

		let block_import_suspender = Arc::new(BlockProductionSuspender::default());

		let peer_syncer =
			PeerBlockSync::new(block_importer_mock.clone(), block_import_suspender.clone());

		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		peer_syncer.sync_block(signed_sidechain_block, &parentchain_header).unwrap();

		assert!(!block_import_suspender.is_suspended().unwrap());
		assert_eq!(1, block_importer_mock.get_imported_blocks().len());
	}

	#[test]
	fn error_is_propagated_if_import_returns_error_other_than_ancestry_mismatch() {
		let block_importer_mock = Arc::new(
			BlockImportMock::<ParentchainBlock, _>::default()
				.with_import_result(Err(Error::InvalidAuthority("auth".to_string()))),
		);

		let block_import_suspender = Arc::new(BlockProductionSuspender::default());

		let peer_syncer =
			PeerBlockSync::new(block_importer_mock.clone(), block_import_suspender.clone());

		let parentchain_header = ParentchainHeaderBuilder::default().build();
		let signed_sidechain_block = SidechainBlockBuilder::default().build_signed();

		let sync_result = peer_syncer.sync_block(signed_sidechain_block, &parentchain_header);

		assert_matches!(sync_result, Err(Error::Other(_)));
		assert!(!block_import_suspender.is_suspended().unwrap());
		assert_eq!(1, block_importer_mock.get_imported_blocks().len());
	}
}
