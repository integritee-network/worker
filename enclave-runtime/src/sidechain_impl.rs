//! Implement sidechain traits that can't be implemented outside.
//!
//! Todo: Once we have put the `top_pool` stuff in an entirely different crate we can
//! move most parts here to the sidechain crate.

use crate::{
	execute_top_pool_trusted_calls, prepare_and_send_xts_and_block, Result as EnclaveResult,
};
use codec::Encode;
use core::time::Duration;
use itc_light_client::{BlockNumberOps, LightClientState, NumberFor, Validator};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::{Aes, AesSeal};
use itp_sgx_io::SealedIO;
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage_verifier::GetStorageVerified;
use its_sidechain::{
	aura::{Aura, AuraVerifier, SlotClaimStrategy},
	consensus_common::{BlockImport, Environment, Error as ConsensusError, Proposal, Proposer},
	primitives::traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock},
	slots::{PerShardSlotWorkerScheduler, SlotInfo},
	state::SidechainDB,
	top_pool_rpc_author::traits::{AuthorApi, OnBlockCreated, SendState},
	validateer_fetch::ValidateerFetch,
};
use log::error;
use primitive_types::H256;
use sgx_externalities::SgxExternalities;
use sp_core::Pair;
use sp_runtime::{traits::Block, MultiSignature};
use std::{marker::PhantomData, string::ToString, sync::Arc, vec::Vec};

///! `SlotProposer` instance that has access to everything needed to propose a sidechain block
pub struct SlotProposer<PB: Block, SB: SignedBlock, OcallApi, Author, StateHandler> {
	ocall_api: Arc<OcallApi>,
	author: Arc<Author>,
	state_handler: Arc<StateHandler>,
	parentchain_header: PB::Header,
	shard: ShardIdentifierFor<SB>,
	_phantom: PhantomData<PB>,
}

///! `ProposerFactory` instance containing all the data to create the `SlotProposer` for the
/// next `Slot`
pub struct ProposerFactory<PB: Block, OcallApi, Author, StateHandler> {
	ocall_api: Arc<OcallApi>,
	author: Arc<Author>,
	state_handler: Arc<StateHandler>,
	_phantom: PhantomData<PB>,
}

impl<PB: Block, OcallApi, Author, StateHandler>
	ProposerFactory<PB, OcallApi, Author, StateHandler>
{
	pub fn new(
		ocall_api: Arc<OcallApi>,
		author: Arc<Author>,
		state_handler: Arc<StateHandler>,
	) -> Self {
		Self { ocall_api, author, state_handler, _phantom: Default::default() }
	}
}

impl<PB: Block<Hash = H256>, SB, OcallApi, Author, StateHandler> Environment<PB, SB>
	for ProposerFactory<PB, OcallApi, Author, StateHandler>
where
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	OcallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi + GetStorageVerified + 'static,
	Author: AuthorApi<H256, PB::Hash>
		+ SendState<Hash = PB::Hash>
		+ OnBlockCreated<Hash = PB::Hash>
		+ Send
		+ Sync,
	StateHandler: HandleState + Send + Sync + 'static,
{
	type Proposer = SlotProposer<PB, SB, OcallApi, Author, StateHandler>;
	type Error = ConsensusError;

	fn init(
		&mut self,
		parent_header: PB::Header,
		shard: ShardIdentifierFor<SB>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(SlotProposer {
			ocall_api: self.ocall_api.clone(),
			author: self.author.clone(),
			state_handler: self.state_handler.clone(),
			parentchain_header: parent_header,
			shard,
			_phantom: PhantomData,
		})
	}
}

impl<PB, SB, OcallApi, Author, StateHandler> Proposer<PB, SB>
	for SlotProposer<PB, SB, OcallApi, Author, StateHandler>
where
	PB: Block<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	OcallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	Author:
		AuthorApi<H256, PB::Hash> + SendState<Hash = PB::Hash> + OnBlockCreated<Hash = PB::Hash>,
	StateHandler: HandleState + Send + Sync + 'static,
{
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SB>, ConsensusError> {
		let (calls, blocks) = execute_top_pool_trusted_calls::<PB, SB, _, _, _>(
			self.ocall_api.as_ref(),
			self.author.as_ref(),
			self.state_handler.as_ref(),
			&self.parentchain_header,
			self.shard,
			max_duration,
		)
		.map_err(|e| ConsensusError::Other(e.to_string().into()))?;

		Ok(Proposal {
			block: blocks.ok_or(ConsensusError::CannotPropose)?,
			parentchain_effects: calls,
		})
	}
}

/// Executes aura for the given `slot`
pub fn exec_aura_on_slot<Authority, PB, SB, OcallApi, LightValidator, PEnvironment>(
	slot: SlotInfo<PB>,
	authority: Authority,
	validator: &mut LightValidator,
	ocall_api: OcallApi,
	proposer_environment: PEnvironment,
	nonce: &mut u32,
	shards: Vec<ShardIdentifierFor<SB>>,
) -> EnclaveResult<()>
where
	// setting the public type is necessary due to some non-generic downstream code.
	Authority: Pair<Public = sp_core::ed25519::Public>,
	Authority::Public: Encode,
	PB: Block<Hash = H256>,
	SB: SignedBlock<Public = Authority::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = Authority::Public>,
	OcallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi + 'static,
	LightValidator: Validator<PB> + LightClientState<PB> + Clone + Send + Sync + 'static,
	NumberFor<PB>: BlockNumberOps,
	PEnvironment: Environment<PB, SB, Error = ConsensusError> + Send + Sync,
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

	prepare_and_send_xts_and_block::<_, SB, _, _>(
		validator,
		&ocall_api,
		xts.into_iter().flatten().collect(),
		blocks,
		nonce,
	)
}

/// Not used now as we skip block import currently.
#[allow(unused)]
pub fn import_sidechain_blocks<PB, SB, O, BI>(
	blocks: Vec<SB>,
	latest_parentchain_header: &PB::Header,
	mut block_importer: BI,
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
pub struct BlockImporter<A, PB, SB, O, ST, StateHandler> {
	state_handler: Arc<StateHandler>,
	_phantom: PhantomData<(A, PB, SB, ST, O)>,
}

impl<A, PB, SB, O, ST, StateHandler> BlockImporter<A, PB, SB, O, ST, StateHandler> {
	#[allow(unused)]
	pub fn new(state_handler: Arc<StateHandler>) -> Self {
		Self { state_handler, _phantom: Default::default() }
	}
}

impl<A, PB, SB, O, StateHandler> BlockImport<PB, SB>
	for BlockImporter<A, PB, SB, O, SidechainDB<SB::Block, SgxExternalities>, StateHandler>
where
	A: Pair,
	A::Public: std::fmt::Debug,
	PB: Block<Hash = H256>,
	SB: SignedBlock<Public = A::Public> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256>,
	O: ValidateerFetch + GetStorageVerified + Send + Sync,
	StateHandler: HandleState,
{
	type Verifier = AuraVerifier<A, PB, SB, SidechainDB<SB::Block, SgxExternalities>, O>;
	type SidechainState = SidechainDB<SB::Block, SgxExternalities>;
	type StateCrypto = Aes;
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

	fn state_key() -> Result<Self::StateCrypto, ConsensusError> {
		AesSeal::unseal()
			.map_err(|e| ConsensusError::Other(format!("Could not unseal: {:?}", e).into()))
	}
}
