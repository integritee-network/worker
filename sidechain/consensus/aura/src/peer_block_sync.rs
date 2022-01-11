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

use crate::block_production_suspension::{IsBlockProductionSuspended, SuspendBlockProduction};
use core::marker::PhantomData;
use its_consensus_common::{BlockImport, Error, Result};
use its_primitives::{traits::SignedBlock as SignedSidechainBlockTrait, types::BlockHash};
use log::*;
use sp_runtime::traits::{Block as ParentchainBlockTrait, Header as ParentchainHeaderTrait};
use std::sync::Arc;

pub trait SyncBlockFromPeer<ParentchainHeader, SignedSidechainBlock>
where
	ParentchainHeader: ParentchainHeaderTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	fn attempt_block_sync(
		&self,
		sidechain_block: SignedSidechainBlock,
		last_imported_parentchain_header: &ParentchainHeader,
	) -> Result<()>;
}

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
	fn sync_blocks_from_peer(
		&self,
		_last_known_block_hash: BlockHash,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<()> {
		// TODO fetch blocks from peer

		let blocks_to_import: Vec<SignedSidechainBlock> = Vec::new();
		for block_to_import in blocks_to_import {
			if let Err(e) =
				self.importer.import_block(block_to_import, last_imported_parentchain_header)
			{
				// If we encounter an error here, we have to abort the sync process, no way to recover.
				error!("Error while importing a block during peer sync process, cannot recover, have to abort");
				return Err(e)
			}
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
	fn attempt_block_sync(
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
		if let Err(Error::BlockAncestryMismatch(_block_number, block_hash, _)) = self
			.importer
			.import_block(sidechain_block.clone(), last_imported_parentchain_header)
		{
			warn!("Got ancestry mismatch error upon block import. Attempting to sync missing blocks from peer");

			// TODO need a 'finally' (or on-drop) here, to always resume block production ?

			// Suspend block production while we sync blocks from peer.
			self.block_production_suspender.suspend()?;

			self.sync_blocks_from_peer(block_hash, last_imported_parentchain_header)?;

			// Second attempt to import the original gossiped sidechain block
			if let Err(e) =
				self.importer.import_block(sidechain_block, last_imported_parentchain_header)
			{
				warn!("Second attempt to import gossiped sidechain block failed: {:?}", e);
			}

			self.block_production_suspender.resume()?;
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {}
