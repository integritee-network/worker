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

//! Implement sidechain traits that can't be implemented outside.
//!
//! Todo: Once we have put the `top_pool` stuff in an entirely different crate we can
//! move most parts here to the sidechain crate.

use crate::{
	sidechain_block_composer::ComposeBlockAndConfirmation,
	top_pool_operation_executor::ExecuteCallsOnTopPool, Result as EnclaveResult,
};
use codec::Encode;
use core::time::Duration;
use itc_light_client::{BlockNumberOps, LightClientState, NumberFor, Validator};
use itp_extrinsics_factory::CreateExtrinsics;
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::StateCrypto;
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage_verifier::GetStorageVerified;
use itp_types::OpaqueCall;
use its_sidechain::{
	aura::{Aura, AuraVerifier, SlotClaimStrategy},
	consensus_common::{BlockImport, Environment, Error as ConsensusError, Proposal, Proposer},
	primitives::traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock},
	slots::{PerShardSlotWorkerScheduler, SlotInfo},
	state::SidechainDB,
	validateer_fetch::ValidateerFetch,
};
use log::error;
use primitive_types::H256;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::{traits::Block, MultiSignature};
use std::{marker::PhantomData, string::ToString, sync::Arc, vec::Vec};

///! `SlotProposer` instance that has access to everything needed to propose a sidechain block
pub struct SlotProposer<PB: Block, SB: SignedBlock, TopPoolExecutor, BlockComposer> {
	top_pool_executor: Arc<TopPoolExecutor>,
	block_composer: Arc<BlockComposer>,
	parentchain_header: PB::Header,
	shard: ShardIdentifierFor<SB>,
	_phantom: PhantomData<PB>,
}

///! `ProposerFactory` instance containing all the data to create the `SlotProposer` for the
/// next `Slot`
pub struct ProposerFactory<PB: Block, TopPoolExecutor, BlockComposer> {
	top_pool_executor: Arc<TopPoolExecutor>,
	block_composer: Arc<BlockComposer>,
	_phantom: PhantomData<PB>,
}

impl<PB: Block, TopPoolExecutor, BlockComposer>
	ProposerFactory<PB, TopPoolExecutor, BlockComposer>
{
	pub fn new(
		top_pool_executor: Arc<TopPoolExecutor>,
		block_composer: Arc<BlockComposer>,
	) -> Self {
		Self { top_pool_executor, block_composer, _phantom: Default::default() }
	}
}

impl<PB: Block<Hash = H256>, SB, TopPoolExecutor, BlockComposer> Environment<PB, SB>
	for ProposerFactory<PB, TopPoolExecutor, BlockComposer>
where
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	TopPoolExecutor: ExecuteCallsOnTopPool<ParentchainBlockT = PB> + Send + Sync + 'static,
	BlockComposer: ComposeBlockAndConfirmation<ParentchainBlockT = PB, SidechainBlockT = SB>
		+ Send
		+ Sync
		+ 'static,
{
	type Proposer = SlotProposer<PB, SB, TopPoolExecutor, BlockComposer>;
	type Error = ConsensusError;

	fn init(
		&mut self,
		parent_header: PB::Header,
		shard: ShardIdentifierFor<SB>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(SlotProposer {
			top_pool_executor: self.top_pool_executor.clone(),
			block_composer: self.block_composer.clone(),
			parentchain_header: parent_header,
			shard,
			_phantom: PhantomData,
		})
	}
}

impl<PB, SB, TopPoolExecutor, BlockComposer> Proposer<PB, SB>
	for SlotProposer<PB, SB, TopPoolExecutor, BlockComposer>
where
	PB: Block<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	TopPoolExecutor: ExecuteCallsOnTopPool<ParentchainBlockT = PB> + Send + Sync + 'static,
	BlockComposer: ComposeBlockAndConfirmation<ParentchainBlockT = PB, SidechainBlockT = SB>
		+ Send
		+ Sync
		+ 'static,
{
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SB>, ConsensusError> {
		let latest_onchain_header = &self.parentchain_header;

		let batch_execution_result = self
			.top_pool_executor
			.execute_trusted_calls(latest_onchain_header, self.shard, max_duration)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		let mut parentchain_extrinsics = batch_execution_result.get_extrinsic_callbacks();

		let executed_operation_hashes =
			batch_execution_result.get_executed_operation_hashes().iter().copied().collect();

		let (confirmation_extrinsic, sidechain_block) = self
			.block_composer
			.compose_block_and_confirmation(
				latest_onchain_header,
				executed_operation_hashes,
				self.shard,
				batch_execution_result.previous_state_hash,
			)
			.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		parentchain_extrinsics.push(confirmation_extrinsic);

		Ok(Proposal { block: sidechain_block, parentchain_effects: parentchain_extrinsics })
	}
}

/// Executes aura for the given `slot`
pub fn exec_aura_on_slot<
	Authority,
	PB,
	SB,
	OCallApi,
	LightValidator,
	PEnvironment,
	ExtrinsicsFactory,
>(
	slot: SlotInfo<PB>,
	authority: Authority,
	validator: &mut LightValidator,
	extrinsics_factory: &ExtrinsicsFactory,
	ocall_api: OCallApi,
	proposer_environment: PEnvironment,
	shards: Vec<ShardIdentifierFor<SB>>,
) -> EnclaveResult<()>
where
	// setting the public type is necessary due to some non-generic downstream code.
	PB: Block<Hash = H256>,
	SB: SignedBlock<Public = Authority::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = Authority::Public>,
	SB::Signature: From<Authority::Signature>,
	Authority: Pair<Public = sp_core::ed25519::Public>,
	Authority::Public: Encode,
	OCallApi:
		EnclaveSidechainOCallApi + EnclaveOnChainOCallApi + EnclaveAttestationOCallApi + 'static,
	LightValidator: Validator<PB> + LightClientState<PB> + Clone + Send + Sync + 'static,
	NumberFor<PB>: BlockNumberOps,
	PEnvironment: Environment<PB, SB, Error = ConsensusError> + Send + Sync,
	ExtrinsicsFactory: CreateExtrinsics,
{
	log::info!("[Aura] Executing aura for slot: {:?}", slot);

	let mut aura =
		Aura::<_, _, SB, PEnvironment, _>::new(authority, ocall_api.clone(), proposer_environment)
			.with_claim_strategy(SlotClaimStrategy::Always)
			.with_allow_delayed_proposal(true);

	let (blocks, xts): (Vec<_>, Vec<_>) =
		PerShardSlotWorkerScheduler::on_slot(&mut aura, slot, shards)
			.into_iter()
			.map(|r| (r.block, r.parentchain_effects))
			.unzip();

	ocall_api.propose_sidechain_blocks(blocks)?;
	let opaque_calls: Vec<OpaqueCall> = xts.into_iter().flatten().collect();

	let xts = extrinsics_factory.create_extrinsics(opaque_calls.as_slice())?;

	validator.send_extrinsics(&ocall_api, xts)?;

	Ok(())
}

/// Not used now as we skip block import currently.
#[allow(unused)]
pub fn import_sidechain_blocks<PB, SB, O, BI>(
	blocks: Vec<SB>,
	latest_parentchain_header: &PB::Header,
	mut block_importer: &BI,
	ocall_api: &O,
) -> EnclaveResult<()>
where
	PB: Block<Hash = H256>,
	SB: SignedBlock + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256>,
	O: ValidateerFetch + GetStorageVerified + Send + Sync,
	BI: BlockImport<PB, SB, Context = O>,
{
	for sb in blocks.into_iter() {
		if let Err(e) = block_importer.import_block(sb, latest_parentchain_header, ocall_api) {
			error!("[Sidechain Block Import]: Could not import block. Error: {:?}", e);
		}
	}

	Ok(())
}

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
	PB: Block<Hash = H256>,
	SB: SignedBlock<Public = A::Public> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256>,
	O: ValidateerFetch + GetStorageVerified + Send + Sync,
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

		let updated_state = mutating_function(SidechainDB::<SB::Block, _>::new(state))?;

		self.state_handler
			.write(updated_state.ext, write_lock, shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(())
	}

	fn state_key(&self) -> Self::StateCrypto {
		self.state_key
	}
}
