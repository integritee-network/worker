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

//! Imports parentchain blocks and executes any indirect calls found in the extrinsics.

use crate::{error::Result, ImportParentchainBlocks};

use ita_stf::ParentchainHeader;
use itc_parentchain_indirect_calls_executor::ExecuteIndirectCalls;
use itc_parentchain_light_client::{
	concurrent_access::ValidatorAccess, BlockNumberOps, ExtrinsicSender, Validator,
};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_stf_executor::traits::StfUpdateState;
use itp_stf_interface::ShardCreationInfo;
use itp_types::{
	parentchain::{GenericMortality, IdentifyParentchain, ParentchainId},
	OpaqueCall, H256,
};
use log::*;
use sp_runtime::{
	generic::{Era, SignedBlock as SignedBlockG},
	traits::{Block as ParentchainBlockTrait, Header as HeaderT, NumberFor},
};
use std::{marker::PhantomData, sync::Arc, vec, vec::Vec};

/// Parentchain block import implementation.
pub struct ParentchainBlockImporter<
	ParentchainBlock,
	ValidatorAccessor,
	StfExecutor,
	ExtrinsicsFactory,
	IndirectCallsExecutor,
> {
	pub validator_accessor: Arc<ValidatorAccessor>,
	stf_executor: Arc<StfExecutor>,
	extrinsics_factory: Arc<ExtrinsicsFactory>,
	pub indirect_calls_executor: Arc<IndirectCallsExecutor>,
	shard_creation_info: ShardCreationInfo,
	pub parentchain_id: ParentchainId,
	_phantom: PhantomData<ParentchainBlock>,
}

impl<
		ParentchainBlock,
		ValidatorAccessor,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	>
	ParentchainBlockImporter<
		ParentchainBlock,
		ValidatorAccessor,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	>
{
	pub fn new(
		validator_accessor: Arc<ValidatorAccessor>,
		stf_executor: Arc<StfExecutor>,
		extrinsics_factory: Arc<ExtrinsicsFactory>,
		indirect_calls_executor: Arc<IndirectCallsExecutor>,
		shard_creation_info: ShardCreationInfo,
		parentchain_id: ParentchainId,
	) -> Self {
		ParentchainBlockImporter {
			validator_accessor,
			stf_executor,
			extrinsics_factory,
			indirect_calls_executor,
			shard_creation_info,
			parentchain_id,
			_phantom: Default::default(),
		}
	}
}

impl<
		ParentchainBlock,
		ValidatorAccessor,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	> ImportParentchainBlocks
	for ParentchainBlockImporter<
		ParentchainBlock,
		ValidatorAccessor,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256, Header = ParentchainHeader>,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock> + IdentifyParentchain,
	StfExecutor: StfUpdateState<ParentchainHeader, ParentchainId>,
	ExtrinsicsFactory: CreateExtrinsics,
	IndirectCallsExecutor: ExecuteIndirectCalls,
{
	type SignedBlockType = SignedBlockG<ParentchainBlock>;

	fn import_parentchain_blocks(
		&self,
		blocks_to_import: Vec<Self::SignedBlockType>,
		events_to_import: Vec<Vec<u8>>,
	) -> Result<()> {
		let mut calls = Vec::<(OpaqueCall, GenericMortality)>::new();
		let id = self.validator_accessor.parentchain_id();

		debug!(
			"[{:?}] Import {} blocks to light-client. event blocks {}",
			id,
			blocks_to_import.len(),
			events_to_import.len()
		);
		let events_to_import_aligned: Vec<Vec<u8>> = if events_to_import.is_empty() {
			vec![vec![]; blocks_to_import.len()]
		} else {
			events_to_import
		};
		for (signed_block, raw_events) in
			blocks_to_import.into_iter().zip(events_to_import_aligned.into_iter())
		{
			if let Err(e) = self
				.validator_accessor
				.execute_mut_on_validator(|v| v.submit_block(&signed_block))
			{
				error!("[{:?}] Header submission to light client failed for block number {} and hash {:?}: {:?}", id, signed_block.block.header().number(), signed_block.block.hash(), e);

				return Err(e.into())
			}

			// check if we can fast-sync
			trace!("Shard creation info {:?}", self.shard_creation_info);
			if let Some(creation_block) = self.shard_creation_info.for_parentchain(id) {
				if signed_block.block.header().number < creation_block.number {
					trace!(
						"[{:?}] fast-syncing block import, ignoring any invocations before block {:}",
						id,
						creation_block.number
					);
					continue
				}
			}

			let block = signed_block.block;
			// Perform state updates.
			if let Err(e) = self
				.stf_executor
				.update_states(block.header(), &self.validator_accessor.parentchain_id())
			{
				error!("[{:?}] Error performing state updates upon block import", id);
				return Err(e.into())
			}

			// Execute indirect calls that were found in the extrinsics of the block,
			// incl. shielding and unshielding.
			match self.indirect_calls_executor.execute_indirect_calls_in_extrinsics(
				&block,
				&raw_events,
				self.extrinsics_factory.genesis_hash(),
			) {
				Ok(Some(confirm_processed_parentchain_block_call)) => {
					let opaque_call = confirm_processed_parentchain_block_call;
					// if we have significant downtime, this mortality means we will not confirm all imported blocks
					let mortality = GenericMortality {
						era: Era::mortal(512, (*block.header().number()).into()),
						mortality_checkpoint: Some(block.hash()),
					};
					calls.push((opaque_call, mortality));
				},
				Ok(None) =>
					trace!("[{:?}] omitting confirmation call to non-integritee parentchain", id),
				Err(e) => error!("[{:?}] Error executing relevant extrinsics: {:?}", id, e),
			};

			info!(
				"[{:?}] Successfully imported parentchain block (number: {}, hash: {})",
				id,
				block.header().number,
				block.header().hash()
			);
		}

		// Create extrinsics for all `block processed` calls we've gathered.
		let parentchain_extrinsics =
			self.extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;

		// Sending the extrinsic requires mut access because the validator caches the sent extrinsics internally.
		self.validator_accessor
			.execute_mut_on_validator(|v| v.send_extrinsics(parentchain_extrinsics))?;

		Ok(())
	}

	fn parentchain_id(&self) -> ParentchainId {
		self.validator_accessor.parentchain_id()
	}
}
