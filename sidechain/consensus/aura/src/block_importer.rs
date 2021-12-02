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

use crate::{AuraVerifier, SidechainBlockT};
use ita_stf::hash::TrustedOperationOrHash;
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::StateCrypto;
use itp_stf_executor::ExecutedOperation;
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage_verifier::GetStorageVerified;
use itp_types::H256;
use its_consensus_common::Error as ConsensusError;
use its_primitives::traits::{Block as BlockT, ShardIdentifierFor, SignedBlock as SignedBlockT};
use its_state::SidechainDB;
use its_top_pool_executor::TopPoolCallOperator;
use its_validateer_fetch::ValidateerFetch;
use log::*;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{marker::PhantomData, sync::Arc, vec::Vec};

/// Implements `BlockImport`. This is not the definite version. This might change depending on the
/// implementation of #423: https://github.com/integritee-network/worker/issues/423 .
#[derive(Clone)]
pub struct BlockImporter<
	Authority,
	PB,
	SB,
	OCallApi,
	SidechainState,
	StateHandler,
	StateKey,
	TopPoolExecutor,
> {
	state_handler: Arc<StateHandler>,
	state_key: StateKey,
	authority: Authority,
	top_pool_executor: Arc<TopPoolExecutor>,
	ocall_api: Arc<OCallApi>,
	_phantom: PhantomData<(PB, SB, SidechainState)>,
}

impl<Authority, PB, SB, OCallApi, SidechainState, StateHandler, StateKey, TopPoolExecutor>
	BlockImporter<Authority, PB, SB, OCallApi, SidechainState, StateHandler, StateKey, TopPoolExecutor>
where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	PB: ParentchainBlockTrait<Hash = H256>,
	SB: SignedBlockT<Public = Authority::Public> + 'static,
	SB::Block: BlockT<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi
		+ EnclaveAttestationOCallApi
		+ ValidateerFetch
		+ GetStorageVerified
		+ Send
		+ Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKey: StateCrypto + Copy,
	TopPoolExecutor: TopPoolCallOperator<PB, SB> + Send + Sync + 'static,
{
	pub fn new(
		state_handler: Arc<StateHandler>,
		state_key: StateKey,
		authority: Authority,
		top_pool_executor: Arc<TopPoolExecutor>,
		ocall_api: Arc<OCallApi>,
	) -> Self {
		Self {
			state_handler,
			state_key,
			authority,
			top_pool_executor,
			ocall_api,
			_phantom: Default::default(),
		}
	}

	pub(crate) fn remove_calls_from_top_pool(
		&self,
		signed_top_hashes: &[H256],
		shard: &ShardIdentifierFor<SB>,
	) {
		let executed_operations = signed_top_hashes
			.iter()
			.map(|hash| {
				// Only successfully executed operations are included in a block.
				ExecutedOperation::success(*hash, TrustedOperationOrHash::Hash(*hash), Vec::new())
			})
			.collect();

		let unremoved_calls =
			self.top_pool_executor.remove_calls_from_pool(shard, executed_operations);

		for unremoved_call in unremoved_calls {
			error!(
				"Could not remove call {:?} from top pool",
				unremoved_call.trusted_operation_or_hash
			);
		}
	}

	pub(crate) fn block_author_is_self(&self, block_author: &SB::Public) -> bool {
		self.authority.public() == *block_author
	}
}

impl<Authority, PB, SB, OCallApi, StateHandler, StateKey, TopPoolExecutor> BlockImport<PB, SB>
	for BlockImporter<
		Authority,
		PB,
		SB,
		OCallApi,
		SidechainDB<SB::Block, SgxExternalities>,
		StateHandler,
		StateKey,
		TopPoolExecutor,
	> where
	Authority: Pair,
	Authority::Public: std::fmt::Debug,
	PB: ParentchainBlockTrait<Hash = H256>,
	SB: SignedBlockT<Public = Authority::Public> + 'static,
	SB::Block: BlockT<ShardIdentifier = H256>,
	OCallApi: EnclaveSidechainOCallApi
		+ EnclaveAttestationOCallApi
		+ ValidateerFetch
		+ GetStorageVerified
		+ Send
		+ Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKey: StateCrypto + Copy,
	TopPoolExecutor: TopPoolCallOperator<PB, SB> + Send + Sync + 'static,
{
	type Verifier =
		AuraVerifier<Authority, PB, SB, SidechainDB<SB::Block, SgxExternalities>, OCallApi>;
	type SidechainState = SidechainDB<SB::Block, SgxExternalities>;
	type StateCrypto = StateKey;
	type Context = OCallApi;

	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier {
		AuraVerifier::<Authority, PB, _, _, _>::new(SLOT_DURATION, state)
	}

	fn apply_state_update<F>(
		&self,
		shard: &ShardIdentifierFor<SB>,
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

	fn cleanup(&self, signed_sidechain_block: &SB) -> Result<(), ConsensusError> {
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
