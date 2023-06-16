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

use crate::{AuraVerifier, EnclaveOnChainOCallApi, SidechainBlockTrait};
use ita_stf::hash::TrustedOperationOrHash;
use itc_parentchain_block_import_dispatcher::triggered_dispatcher::TriggerParentchainBlockImport;
use itp_enclave_metrics::EnclaveMetric;
use itp_ocall_api::{EnclaveMetricsOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::{key_repository::AccessKey, StateCrypto};
use itp_sgx_externalities::SgxExternalities;
use itp_stf_state_handler::handle_state::HandleState;
use itp_top_pool_author::traits::{AuthorApi, OnBlockImported};
use itp_types::H256;
use its_consensus_common::Error as ConsensusError;
use its_primitives::traits::{
	BlockData, Header as HeaderTrait, ShardIdentifierFor, SignedBlock as SignedBlockTrait,
};
use its_validateer_fetch::ValidateerFetch;
use log::*;
use sp_core::Pair;
use sp_runtime::{
	generic::SignedBlock as SignedParentchainBlock,
	traits::{Block as ParentchainBlockTrait, Header},
};
use std::{marker::PhantomData, sync::Arc};

/// Implements `BlockImport`.
#[derive(Clone)]
pub struct BlockImporter<
	Authority,
	ParentchainBlock,
	SignedSidechainBlock,
	OCallApi,
	StateHandler,
	StateKeyRepository,
	TopPoolAuthor,
	ParentchainBlockImporter,
> {
	state_handler: Arc<StateHandler>,
	state_key_repository: Arc<StateKeyRepository>,
	top_pool_author: Arc<TopPoolAuthor>,
	parentchain_block_importer: Arc<ParentchainBlockImporter>,
	ocall_api: Arc<OCallApi>,
	_phantom: PhantomData<(Authority, ParentchainBlock, SignedSidechainBlock)>,
}

impl<
		Authority,
		ParentchainBlock,
		SignedSidechainBlock,
		OCallApi,
		StateHandler,
		StateKeyRepository,
		TopPoolAuthor,
		ParentchainBlockImporter,
	>
	BlockImporter<
		Authority,
		ParentchainBlock,
		SignedSidechainBlock,
		OCallApi,
		StateHandler,
		StateKeyRepository,
		TopPoolAuthor,
		ParentchainBlockImporter,
	> where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock: SignedBlockTrait<Public = Authority::Public> + 'static,
	<<SignedSidechainBlock as SignedBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi
		+ ValidateerFetch
		+ EnclaveOnChainOCallApi
		+ EnclaveMetricsOCallApi
		+ Send
		+ Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKeyRepository: AccessKey,
	<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
	TopPoolAuthor: AuthorApi<H256, H256> + OnBlockImported<Hash = H256>,
	ParentchainBlockImporter: TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>
		+ Send
		+ Sync,
{
	pub fn new(
		state_handler: Arc<StateHandler>,
		state_key_repository: Arc<StateKeyRepository>,
		top_pool_author: Arc<TopPoolAuthor>,
		parentchain_block_importer: Arc<ParentchainBlockImporter>,
		ocall_api: Arc<OCallApi>,
	) -> Self {
		Self {
			state_handler,
			state_key_repository,
			top_pool_author,
			parentchain_block_importer,
			ocall_api,
			_phantom: Default::default(),
		}
	}

	fn update_top_pool(&self, sidechain_block: &SignedSidechainBlock::Block) {
		// Notify pool about imported block for status updates of the calls.
		self.top_pool_author.on_block_imported(
			sidechain_block.block_data().signed_top_hashes(),
			sidechain_block.hash(),
		);

		// Remove calls from pool.
		let executed_operations = sidechain_block
			.block_data()
			.signed_top_hashes()
			.iter()
			.map(|hash| (TrustedOperationOrHash::Hash(*hash), true))
			.collect();

		let _calls_failed_to_remove = self
			.top_pool_author
			.remove_calls_from_pool(sidechain_block.header().shard_id(), executed_operations);

		// In case the executed call did not originate in our own TOP pool, we will not be able to remove it from our TOP pool.
		// So this error will occur frequently, without it meaning that something really went wrong.
		// TODO: Once the TOP pools are synchronized, we will want this check again!
		// for call_failed_to_remove in _calls_failed_to_remove {
		// 	error!("Could not remove call {:?} from top pool", call_failed_to_remove);
		// }
	}
}

impl<
		Authority,
		ParentchainBlock,
		SignedSidechainBlock,
		OCallApi,
		StateHandler,
		StateKeyRepository,
		TopPoolAuthor,
		ParentchainBlockImporter,
	> BlockImport<ParentchainBlock, SignedSidechainBlock>
	for BlockImporter<
		Authority,
		ParentchainBlock,
		SignedSidechainBlock,
		OCallApi,
		StateHandler,
		StateKeyRepository,
		TopPoolAuthor,
		ParentchainBlockImporter,
	> where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock: SignedBlockTrait<Public = Authority::Public> + 'static,
	<<SignedSidechainBlock as SignedBlockTrait>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi
		+ ValidateerFetch
		+ EnclaveOnChainOCallApi
		+ EnclaveMetricsOCallApi
		+ Send
		+ Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKeyRepository: AccessKey,
	<StateKeyRepository as AccessKey>::KeyType: StateCrypto,
	TopPoolAuthor: AuthorApi<H256, H256> + OnBlockImported<Hash = H256>,
	ParentchainBlockImporter: TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>
		+ Send
		+ Sync,
{
	type Verifier = AuraVerifier<Authority, ParentchainBlock, SignedSidechainBlock, OCallApi>;
	type SidechainState = SgxExternalities;
	type StateCrypto = <StateKeyRepository as AccessKey>::KeyType;
	type Context = OCallApi;

	fn verifier(
		&self,
		maybe_last_sidechain_block: Option<SignedSidechainBlock::Block>,
	) -> Self::Verifier {
		AuraVerifier::<Authority, ParentchainBlock, _, _>::new(
			SLOT_DURATION,
			maybe_last_sidechain_block,
		)
	}

	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		mutating_function: F,
	) -> Result<(), ConsensusError>
	where
		F: FnOnce(Self::SidechainState) -> Result<Self::SidechainState, ConsensusError>,
	{
		let (write_lock, state) = self
			.state_handler
			.load_for_mutation(shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		// We load a copy of the state and apply the update. In case the update fails, we don't write
		// the state back to the state handler, and thus guaranteeing state integrity.
		let updated_state = mutating_function(state)?;

		self.state_handler
			.write_after_mutation(updated_state, write_lock, shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(())
	}

	fn verify_import<F>(
		&self,
		shard: &ShardIdentifierFor<SignedSidechainBlock>,
		verifying_function: F,
	) -> Result<SignedSidechainBlock, ConsensusError>
	where
		F: FnOnce(&Self::SidechainState) -> Result<SignedSidechainBlock, ConsensusError>,
	{
		self.state_handler
			.execute_on_current(shard, |state, _| verifying_function(state))
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?
	}

	fn state_key(&self) -> Result<Self::StateCrypto, ConsensusError> {
		self.state_key_repository
			.retrieve_key()
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))
	}

	fn get_context(&self) -> &Self::Context {
		&self.ocall_api
	}

	fn import_parentchain_block(
		&self,
		sidechain_block: &SignedSidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, ConsensusError> {
		// We trigger the import of parentchain blocks up until the last one we've seen in the
		// sidechain block that we're importing. This is done to prevent forks in the sidechain (#423)
		let maybe_latest_imported_block = self
			.parentchain_block_importer
			.import_until(|signed_parentchain_block| {
				signed_parentchain_block.block.hash()
					== sidechain_block.block_data().layer_one_head()
			})
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(maybe_latest_imported_block
			.map(|b| b.block.header().clone())
			.unwrap_or_else(|| last_imported_parentchain_header.clone()))
	}

	fn peek_parentchain_header(
		&self,
		sidechain_block: &SignedSidechainBlock::Block,
		last_imported_parentchain_header: &ParentchainBlock::Header,
	) -> Result<ParentchainBlock::Header, ConsensusError> {
		let parentchain_header_hash_to_peek = sidechain_block.block_data().layer_one_head();
		if parentchain_header_hash_to_peek == last_imported_parentchain_header.hash() {
			debug!("No queue peek necessary, sidechain block references latest imported parentchain block");
			return Ok(last_imported_parentchain_header.clone())
		}

		let maybe_signed_parentchain_block = self
			.parentchain_block_importer
			.peek(|parentchain_block| {
				parentchain_block.block.header().hash() == parentchain_header_hash_to_peek
			})
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		maybe_signed_parentchain_block
			.map(|signed_block| signed_block.block.header().clone())
			.ok_or_else(|| {
				ConsensusError::Other(
					format!(
						"Failed to find parentchain header in import queue (hash: {}) that is \
			associated with the current sidechain block that is to be imported (number: {}, hash: {})",
						parentchain_header_hash_to_peek,
						sidechain_block.header().block_number(),
						sidechain_block.hash()
					)
					.into(),
				)
			})
	}

	fn cleanup(&self, signed_sidechain_block: &SignedSidechainBlock) -> Result<(), ConsensusError> {
		let sidechain_block = signed_sidechain_block.block();

		// Remove all successfully applied trusted calls from the top pool.
		self.update_top_pool(sidechain_block);

		// Send metric about sidechain block height (i.e. block number)
		let block_height_metric =
			EnclaveMetric::SetSidechainBlockHeight(sidechain_block.header().block_number());
		if let Err(e) = self.ocall_api.update_metric(block_height_metric) {
			warn!("Failed to update sidechain block height metric: {:?}", e);
		}

		Ok(())
	}
}
