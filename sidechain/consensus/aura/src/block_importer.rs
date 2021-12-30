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
//! Implementation of the sidechain block importer struct.
//! Imports sidechain blocks and applies the accompanying state diff to its state.

// Reexport BlockImport trait which implements fn block_import()
pub use its_consensus_common::BlockImport;

use crate::{AuraVerifier, SidechainBlockTrait};
use ita_stf::hash::TrustedOperationOrHash;
use itc_parentchain_block_import_dispatcher::triggered_dispatcher::TriggerParentchainBlockImport;
use itp_ocall_api::EnclaveSidechainOCallApi;
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::StateCrypto;
use itp_stf_executor::ExecutedOperation;
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage_verifier::GetStorageVerified;
use itp_types::H256;
use its_consensus_common::Error as ConsensusError;
use its_primitives::traits::{
	Block as BlockTrait, ShardIdentifierFor, SignedBlock as SignedBlockTrait,
};
use its_state::SidechainDB;
use its_top_pool_executor::TopPoolCallOperator;
use its_validateer_fetch::ValidateerFetch;
use log::*;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::{
	generic::SignedBlock as SignedParentchainBlockGeneric, traits::Block as ParentchainBlockTrait,
};
use std::{marker::PhantomData, sync::Arc, vec::Vec};

/// Implements `BlockImport`.
#[derive(Clone)]
pub struct BlockImporter<
	Authority,
	ParentchainBlock,
	SidechainBlock,
	OCallApi,
	SidechainState,
	StateHandler,
	StateKey,
	TopPoolExecutor,
	ParentchainBlockImportTrigger,
> {
	state_handler: Arc<StateHandler>,
	state_key: StateKey,
	authority: Authority,
	top_pool_executor: Arc<TopPoolExecutor>,
	parentchain_block_import_trigger: Arc<ParentchainBlockImportTrigger>,
	ocall_api: Arc<OCallApi>,
	_phantom: PhantomData<(ParentchainBlock, SidechainBlock, SidechainState)>,
}

impl<
		Authority,
		ParentchainBlock,
		SidechainBlock,
		OCallApi,
		SidechainState,
		StateHandler,
		StateKey,
		TopPoolExecutor,
		ParentchainBlockImportTrigger,
	>
	BlockImporter<
		Authority,
		ParentchainBlock,
		SidechainBlock,
		OCallApi,
		SidechainState,
		StateHandler,
		StateKey,
		TopPoolExecutor,
		ParentchainBlockImportTrigger,
	> where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SidechainBlock: SignedBlockTrait<Public = Authority::Public> + 'static,
	SidechainBlock::Block: BlockTrait<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi + ValidateerFetch + GetStorageVerified + Send + Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKey: StateCrypto + Copy,
	TopPoolExecutor: TopPoolCallOperator<ParentchainBlock, SidechainBlock> + Send + Sync + 'static,
	ParentchainBlockImportTrigger: TriggerParentchainBlockImport<SignedParentchainBlockGeneric<ParentchainBlock>>
		+ Send
		+ Sync,
{
	pub fn new(
		state_handler: Arc<StateHandler>,
		state_key: StateKey,
		authority: Authority,
		top_pool_executor: Arc<TopPoolExecutor>,
		parentchain_block_import_trigger: Arc<ParentchainBlockImportTrigger>,
		ocall_api: Arc<OCallApi>,
	) -> Self {
		Self {
			state_handler,
			state_key,
			authority,
			top_pool_executor,
			parentchain_block_import_trigger,
			ocall_api,
			_phantom: Default::default(),
		}
	}

	pub(crate) fn remove_calls_from_top_pool(
		&self,
		signed_top_hashes: &[H256],
		shard: &ShardIdentifierFor<SidechainBlock>,
	) {
		let executed_operations = signed_top_hashes
			.iter()
			.map(|hash| {
				// Only successfully executed operations are included in a block.
				ExecutedOperation::success(*hash, TrustedOperationOrHash::Hash(*hash), Vec::new())
			})
			.collect();
		// FIXME: we should take the rpc author here directly #547
		let unremoved_calls =
			self.top_pool_executor.remove_calls_from_pool(shard, executed_operations);

		for unremoved_call in unremoved_calls {
			error!(
				"Could not remove call {:?} from top pool",
				unremoved_call.trusted_operation_or_hash
			);
		}
	}

	pub(crate) fn block_author_is_self(&self, block_author: &SidechainBlock::Public) -> bool {
		self.authority.public() == *block_author
	}
}

impl<
		Authority,
		ParentchainBlock,
		SidechainBlock,
		OCallApi,
		StateHandler,
		StateKey,
		TopPoolExecutor,
		ParentchainBlockImportTrigger,
	> BlockImport<ParentchainBlock, SidechainBlock>
	for BlockImporter<
		Authority,
		ParentchainBlock,
		SidechainBlock,
		OCallApi,
		SidechainDB<SidechainBlock::Block, SgxExternalities>,
		StateHandler,
		StateKey,
		TopPoolExecutor,
		ParentchainBlockImportTrigger,
	> where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SidechainBlock: SignedBlockTrait<Public = Authority::Public> + 'static,
	SidechainBlock::Block: BlockTrait<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi + ValidateerFetch + GetStorageVerified + Send + Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKey: StateCrypto + Copy,
	TopPoolExecutor: TopPoolCallOperator<ParentchainBlock, SidechainBlock> + Send + Sync + 'static,
	ParentchainBlockImportTrigger: TriggerParentchainBlockImport<SignedParentchainBlockGeneric<ParentchainBlock>>
		+ Send
		+ Sync,
{
	type Verifier = AuraVerifier<
		Authority,
		ParentchainBlock,
		SidechainBlock,
		SidechainDB<SidechainBlock::Block, SgxExternalities>,
		OCallApi,
	>;
	type SidechainState = SidechainDB<SidechainBlock::Block, SgxExternalities>;
	type StateCrypto = StateKey;
	type Context = OCallApi;

	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier {
		AuraVerifier::<Authority, ParentchainBlock, _, _, _>::new(SLOT_DURATION, state)
	}

	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SidechainBlock>,
		mutating_function: F,
	) -> Result<(), ConsensusError>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState, ConsensusError>,
	{
		let (write_lock, state) = self
			.state_handler
			.load_for_mutation(shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		let updated_state = mutating_function(Self::SidechainState::new(state))?;

		self.state_handler
			.write(updated_state.ext, write_lock, shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(())
	}

	fn state_key(&self) -> Self::StateCrypto {
		self.state_key
	}

	fn get_context(&self) -> &Self::Context {
		&self.ocall_api
	}

	fn handle_import_error(
		&self,
		signed_sidechain_block: &SidechainBlock,
		error: ConsensusError,
	) -> Result<(), ConsensusError> {
		match error {
			ConsensusError::BlockAncestryMismatch(_last_imported_number, ref msg) => {
				//FIXME: We should trigger block production suspension (TBD) here.
				warn!("Could not import block {:?} due to: {:?}.", signed_sidechain_block, msg);
			},
			// Some erros, such as invalid author, should be ignored because we do not want
			// to provide possible attack vectors.
			_ => warn!("Ignoring import error of block {:?}.", signed_sidechain_block),
		}

		Err(error)
	}

	fn import_parentchain_block(
		&self,
		sidechain_block: &SidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, ConsensusError> {
		// We trigger the import of parentchain blocks up until the last one we've seen in the
		// sidechain block that we're importing. This is done to prevent forks in the sidechain (#423)
		let maybe_latest_imported_block = self
			.parentchain_block_import_trigger
			.import_until(|signed_parentchain_block| {
				signed_parentchain_block.block.hash() == sidechain_block.layer_one_head()
			})
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(maybe_latest_imported_block
			.map(|b| b.block.header().clone())
			.unwrap_or_else(|| last_imported_parentchain_header.clone()))
	}

	fn cleanup(&self, signed_sidechain_block: &SidechainBlock) -> Result<(), ConsensusError> {
		let sidechain_block = signed_sidechain_block.block();

		// If the block has been proposed by this enclave, remove all successfully applied
		// trusted calls from the top pool.
		if self.block_author_is_self(sidechain_block.block_author()) {
			self.remove_calls_from_top_pool(
				sidechain_block.signed_top_hashes(),
				&sidechain_block.shard_id(),
			)
		}
		Ok(())
	}
}
