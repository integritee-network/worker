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

use crate::{
	beefy_merkle_tree::{merkle_root, Keccak256},
	error::Result,
	ImportParentchainBlocks,
};
use ita_stf::ParentchainHeader;
use itc_parentchain_indirect_calls_executor::ExecuteIndirectCalls;
use itc_parentchain_light_client::{
	concurrent_access::ValidatorAccess, BlockNumberOps, ExtrinsicSender, LightClientState,
	Validator,
};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::node::{PROCESSED_PARENTCHAIN_BLOCK, TEEREX_MODULE};
use itp_stf_executor::traits::StfUpdateState;
use itp_types::{OpaqueCall, H256};
use log::*;
use sp_runtime::{
	generic::SignedBlock as SignedBlockG,
	traits::{Block as ParentchainBlockTrait, NumberFor},
};
use std::{marker::PhantomData, sync::Arc, vec::Vec};

/// Parentchain block import implementation.
pub struct ParentchainBlockImporter<
	ParentchainBlock,
	ValidatorAccessor,
	OCallApi,
	StfExecutor,
	ExtrinsicsFactory,
	IndirectCallsExecutor,
> where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock, OCallApi>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StfExecutor: StfUpdateState,
	ExtrinsicsFactory: CreateExtrinsics,
	IndirectCallsExecutor: ExecuteIndirectCalls,
{
	validator_accessor: Arc<ValidatorAccessor>,
	stf_executor: Arc<StfExecutor>,
	extrinsics_factory: Arc<ExtrinsicsFactory>,
	indirect_calls_executor: Arc<IndirectCallsExecutor>,
	_phantom: PhantomData<(ParentchainBlock, OCallApi)>,
}

impl<
		ParentchainBlock,
		ValidatorAccessor,
		OCallApi,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	>
	ParentchainBlockImporter<
		ParentchainBlock,
		ValidatorAccessor,
		OCallApi,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	> where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256, Header = ParentchainHeader>,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock, OCallApi>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StfExecutor: StfUpdateState,
	ExtrinsicsFactory: CreateExtrinsics,
	IndirectCallsExecutor: ExecuteIndirectCalls,
{
	pub fn new(
		validator_accessor: Arc<ValidatorAccessor>,
		stf_executor: Arc<StfExecutor>,
		extrinsics_factory: Arc<ExtrinsicsFactory>,
		indirect_calls_executor: Arc<IndirectCallsExecutor>,
	) -> Self {
		ParentchainBlockImporter {
			validator_accessor,
			stf_executor,
			extrinsics_factory,
			indirect_calls_executor,
			_phantom: Default::default(),
		}
	}
}

impl<
		ParentchainBlock,
		ValidatorAccessor,
		OCallApi,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	> ImportParentchainBlocks
	for ParentchainBlockImporter<
		ParentchainBlock,
		ValidatorAccessor,
		OCallApi,
		StfExecutor,
		ExtrinsicsFactory,
		IndirectCallsExecutor,
	> where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256, Header = ParentchainHeader>,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock, OCallApi>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StfExecutor: StfUpdateState,
	ExtrinsicsFactory: CreateExtrinsics,
	IndirectCallsExecutor: ExecuteIndirectCalls,
{
	type SignedBlockType = SignedBlockG<ParentchainBlock>;

	fn import_parentchain_blocks(
		&self,
		blocks_to_import: Vec<Self::SignedBlockType>,
	) -> Result<()> {
		let mut calls = Vec::<OpaqueCall>::new();

		debug!("Import blocks to light-client!");
		for signed_block in blocks_to_import.into_iter() {
			// Check if there are any extrinsics in the to-be-imported block that we sent and cached in the light-client before.
			// If so, remove them now from the cache.
			if let Err(e) = self.validator_accessor.execute_mut_on_validator(|v| {
				v.check_xt_inclusion(v.num_relays(), &signed_block.block)?;

				v.submit_block(v.num_relays(), &signed_block)
			}) {
				error!("[Validator] Header submission failed: {:?}", e);
				return Err(e.into())
			}

			let block = signed_block.block;
			// Perform state updates.
			if let Err(e) = self.stf_executor.update_states(block.header()) {
				error!("Error performing state updates upon block import");
				return Err(e.into())
			}

			// Execute indirect calls that were found in the extrinsics of the block,
			// incl. shielding and unshielding.
			match self.indirect_calls_executor.execute_indirect_calls_in_extrinsics(&block) {
				Ok(executed_shielding_calls) => {
					// Include a processed parentchain block confirmation for each block.
					calls.push(create_processed_parentchain_block_call(
						block.hash(),
						executed_shielding_calls,
					));
				},
				Err(_) => error!("Error executing relevant extrinsics"),
			};

			info!(
				"Successfully imported parentchain block (number: {}, hash: {})",
				block.header().number,
				block.header().hash()
			);
		}

		// Create extrinsics for all `unshielding` and `block processed` calls we've gathered.
		let parentchain_extrinsics =
			self.extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;

		// Sending the extrinsic requires mut access because the validator caches the sent extrinsics internally.
		self.validator_accessor
			.execute_mut_on_validator(|v| v.send_extrinsics(parentchain_extrinsics))?;

		Ok(())
	}
}

/// Creates a processed_parentchain_block extrinsic for a given parentchain block hash and the merkle executed extrinsics.
///
/// Calculates the merkle root of the extrinsics. In case no extrinsics are supplied, the root will be a hash filled with zeros.
fn create_processed_parentchain_block_call(block_hash: H256, extrinsics: Vec<H256>) -> OpaqueCall {
	let root: H256 = merkle_root::<Keccak256, _, _>(extrinsics).into();
	OpaqueCall::from_tuple(&([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, root))
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use codec::Encode;

	#[test]
	fn ensure_empty_extrinsic_vec_triggers_zero_filled_merkle_root() {
		// given
		let block_hash = H256::from([1; 32]);
		let extrinsics = Vec::new();
		let expected_call =
			([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, H256::default()).encode();

		// when
		let call = create_processed_parentchain_block_call(block_hash, extrinsics);

		// then
		assert_eq!(call.0, expected_call);
	}

	#[test]
	fn ensure_non_empty_extrinsic_vec_triggers_non_zero_merkle_root() {
		// given
		let block_hash = H256::from([1; 32]);
		let extrinsics = vec![H256::from([4; 32]), H256::from([9; 32])];
		let zero_root_call =
			([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, H256::default()).encode();

		// when
		let call = create_processed_parentchain_block_call(block_hash, extrinsics);

		// then
		assert_ne!(call.0, zero_root_call);
	}
}
