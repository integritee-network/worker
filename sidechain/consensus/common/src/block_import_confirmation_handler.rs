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
use itc_parentchain_light_client::{
	concurrent_access::ValidatorAccess, BlockNumberOps, ExtrinsicSender, NumberFor,
};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api_metadata::{pallet_sidechain::SidechainCallIndexes, NodeMetadataTrait};
use itp_node_api_metadata_provider::AccessNodeMetadata;
use itp_settings::worker::BLOCK_NUMBER_FINALIZATION_DIFF;
use itp_types::{OpaqueCall, ShardIdentifier};
use its_primitives::traits::Header as HeaderTrait;
use log::*;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{marker::PhantomData, sync::Arc};

/// Trait to confirm a sidechain block import.
pub trait ConfirmBlockImport<SidechainHeader> {
	fn confirm_import(&self, header: &SidechainHeader, shard: &ShardIdentifier) -> Result<()>;
}

/// Creates and sends a sidechain block import confirmation extrsinic to the parentchain.
pub struct BlockImportConfirmationHandler<
	ParentchainBlock,
	SidechainHeader,
	NodeMetadataRepository,
	ExtrinsicsFactory,
	ValidatorAccessor,
> {
	metadata_repository: Arc<NodeMetadataRepository>,
	extrinsics_factory: Arc<ExtrinsicsFactory>,
	validator_accessor: Arc<ValidatorAccessor>,
	_phantom: PhantomData<(ParentchainBlock, SidechainHeader)>,
}

impl<
		ParentchainBlock,
		SidechainHeader,
		NodeMetadataRepository,
		ExtrinsicsFactory,
		ValidatorAccessor,
	>
	BlockImportConfirmationHandler<
		ParentchainBlock,
		SidechainHeader,
		NodeMetadataRepository,
		ExtrinsicsFactory,
		ValidatorAccessor,
	>
{
	pub fn new(
		metadata_repository: Arc<NodeMetadataRepository>,
		extrinsics_factory: Arc<ExtrinsicsFactory>,
		validator_accessor: Arc<ValidatorAccessor>,
	) -> Self {
		Self {
			metadata_repository,
			extrinsics_factory,
			validator_accessor,
			_phantom: Default::default(),
		}
	}
}

impl<
		ParentchainBlock,
		SidechainHeader,
		NodeMetadataRepository,
		ExtrinsicsFactory,
		ValidatorAccessor,
	> ConfirmBlockImport<SidechainHeader>
	for BlockImportConfirmationHandler<
		ParentchainBlock,
		SidechainHeader,
		NodeMetadataRepository,
		ExtrinsicsFactory,
		ValidatorAccessor,
	> where
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	SidechainHeader: HeaderTrait,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
	ExtrinsicsFactory: CreateExtrinsics,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock> + Send + Sync + 'static,
{
	fn confirm_import(&self, header: &SidechainHeader, shard: &ShardIdentifier) -> Result<()> {
		let call = self
			.metadata_repository
			.get_from_metadata(|m| m.confirm_imported_sidechain_block_indexes())
			.map_err(|e| Error::Other(e.into()))?
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

		if header.block_number() == header.next_finalization_block_number() {
			let opaque_call = OpaqueCall::from_tuple(&(
				call,
				shard,
				header.block_number(),
				header.next_finalization_block_number() + BLOCK_NUMBER_FINALIZATION_DIFF,
				header.hash(),
			));

			let xts = self
				.extrinsics_factory
				.create_extrinsics(&[opaque_call], None)
				.map_err(|e| Error::Other(e.into()))?;

			debug!("Sending sidechain block import confirmation extrinsic..");
			self.validator_accessor
				.execute_mut_on_validator(|v| v.send_extrinsics(xts))
				.map_err(|e| Error::Other(e.into()))?;
		}
		Ok(())
	}
}
