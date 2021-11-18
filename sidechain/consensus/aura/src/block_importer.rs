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
use crate::AuraVerifier;
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::StateCrypto;
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage_verifier::GetStorageVerified;
use itp_types::H256;
use its_consensus_common::Error as ConsensusError;
use its_primitives::traits::{Block as BlockT, ShardIdentifierFor, SignedBlock as SignedBlockT};
use its_state::SidechainDB;
use its_validateer_fetch::ValidateerFetch;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{marker::PhantomData, sync::Arc};

// Reexport BlockImport trait which implements fn block_import()
pub use its_consensus_common::BlockImport;

/// Implements `BlockImport`. This is not the definite version. This might change depending on the
/// implementation of #423: https://github.com/integritee-network/worker/issues/423
#[derive(Clone)]
pub struct BlockImporter<A, PB, SB, O, ST, StateHandler, StateKey> {
	state_handler: Arc<StateHandler>,
	state_key: StateKey,
	_phantom: PhantomData<(A, PB, SB, ST, O)>,
}

impl<A, PB, SB, O, ST, StateHandler, StateKey>
	BlockImporter<A, PB, SB, O, ST, StateHandler, StateKey>
{
	#[allow(unused)]
	pub fn new(state_handler: Arc<StateHandler>, state_key: StateKey) -> Self {
		Self { state_handler, state_key, _phantom: Default::default() }
	}
}

impl<A, PB, SB, O, StateHandler, StateKey> BlockImport<PB, SB>
	for BlockImporter<A, PB, SB, O, SidechainDB<SB::Block, SgxExternalities>, StateHandler, StateKey>
where
	A: Pair,
	A::Public: std::fmt::Debug,
	PB: ParentchainBlockTrait<Hash = H256>,
	SB: SignedBlockT<Public = A::Public> + 'static,
	SB::Block: BlockT<ShardIdentifier = H256>,
	O: EnclaveSidechainOCallApi
		+ EnclaveAttestationOCallApi
		+ ValidateerFetch
		+ GetStorageVerified
		+ Send
		+ Sync,
	StateHandler: HandleState<StateT = SgxExternalities>,
	StateKey: StateCrypto + Copy,
{
	type Verifier = AuraVerifier<A, PB, SB, SidechainDB<SB::Block, SgxExternalities>, O>;
	type SidechainState = SidechainDB<SB::Block, SgxExternalities>;
	type StateCrypto = StateKey;
	type Context = O;

	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier {
		AuraVerifier::<A, PB, _, _, _>::new(SLOT_DURATION, state)
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
}
