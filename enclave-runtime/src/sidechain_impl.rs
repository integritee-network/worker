//! Implement sidechain traits that can't be implemented outside.
//!
//! Todo: Once we have put the `top_pool` stuff in an entirely different crate we can
//! move most parts here to the sidechain crate.

use crate::{
	exec_tops, prepare_and_send_xts_and_block,
	rpc::author::{AuthorApi, OnBlockCreated, SendState},
	state::load,
	Result as EnclaveResult,
};
use codec::Encode;
use core::time::Duration;
use itc_light_client::{BlockNumberOps, LightClientState, NumberFor, Validator};
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::{Aes, AesSeal};
use itp_sgx_io::SealedIO;
use itp_storage_verifier::GetStorageVerified;
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
use sp_std::prelude::Vec;
use std::{marker::PhantomData, string::ToString, sync::Arc};

///! `SlotProposer` instance that has access to everything needed to propose a sidechain block
pub struct SlotProposer<PB: Block, SB: SignedBlock, Pair, OcallApi, LightClient, Author> {
	pub ocall_api: Arc<OcallApi>,
	pub light_client: Arc<LightClient>,
	pub author: Arc<Author>,
	pub proposer_key: Pair,
	pub parentchain_header: PB::Header,
	pub shard: ShardIdentifierFor<SB>,
	_phantom: PhantomData<PB>,
}

///! `ProposerFactory` instance containing all the data to create the `SlotProposer` for the
/// next `Slot`
pub struct ProposerFactory<PB: Block, Pair, OcallApi, LightClient, Author> {
	pub ocall_api: Arc<OcallApi>,
	pub light_client: Arc<LightClient>,
	pub author: Arc<Author>,
	pub pair: Pair,
	_phantom: PhantomData<PB>,
}

impl<PB: Block, Pair, OcallApi, LightClient, Author>
	ProposerFactory<PB, Pair, OcallApi, LightClient, Author>
{
	pub fn new(
		ocall_api: Arc<OcallApi>,
		light_client: Arc<LightClient>,
		author: Arc<Author>,
		pair: Pair,
	) -> Self {
		Self { ocall_api, light_client, author, pair, _phantom: Default::default() }
	}
}

impl<PB: Block<Hash = H256>, SB, P, OcallApi, LightClient, Author> Environment<PB, SB>
	for ProposerFactory<PB, P, OcallApi, LightClient, Author>
where
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	P: Pair,
	P::Public: Encode,
	OcallApi: EnclaveOnChainOCallApi + GetStorageVerified + 'static,
	LightClient: Validator<PB> + Send + Sync + 'static,
	Author: AuthorApi<H256, PB::Hash>
		+ SendState<Hash = PB::Hash>
		+ OnBlockCreated<Hash = PB::Hash>
		+ Send
		+ Sync,
{
	type Proposer = SlotProposer<PB, SB, P, OcallApi, LightClient, Author>;
	type Error = ConsensusError;

	fn init(
		&mut self,
		parent_header: PB::Header,
		shard: ShardIdentifierFor<SB>,
	) -> Result<Self::Proposer, Self::Error> {
		Ok(SlotProposer {
			ocall_api: self.ocall_api.clone(),
			light_client: self.light_client.clone(),
			author: self.author.clone(),
			proposer_key: self.pair.clone(),
			parentchain_header: parent_header,
			shard,
			_phantom: PhantomData,
		})
	}
}

impl<PB, SB, Pair, OcallApi, LightClient, Author> Proposer<PB, SB>
	for SlotProposer<PB, SB, Pair, OcallApi, LightClient, Author>
where
	PB: Block<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	SB: SignedBlock<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	OcallApi: EnclaveOnChainOCallApi,
	LightClient: Validator<PB> + Send + Sync + 'static,
	Author:
		AuthorApi<H256, PB::Hash> + SendState<Hash = PB::Hash> + OnBlockCreated<Hash = PB::Hash>,
{
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SB>, ConsensusError> {
		let (calls, blocks) = exec_tops::<PB, SB, _, _>(
			self.ocall_api.as_ref(),
			self.author.as_ref(),
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
pub fn exec_aura_on_slot<Authority, PB, SB, OcallApi, LightValidator, Author>(
	slot: SlotInfo<PB>,
	authority: Authority,
	rpc_author: Author,
	validator: &mut LightValidator,
	ocall_api: OcallApi,
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
	OcallApi: EnclaveOnChainOCallApi + 'static,
	LightValidator: Validator<PB> + LightClientState<PB> + Clone + Send + Sync + 'static,
	NumberFor<PB>: BlockNumberOps,
	Author: AuthorApi<H256, PB::Hash>
		+ SendState<Hash = PB::Hash>
		+ OnBlockCreated<Hash = PB::Hash>
		+ Send
		+ Sync,
{
	log::info!("[Aura] Executing aura for slot: {:?}", slot);

	let env = ProposerFactory::new(
		Arc::new(ocall_api.clone()),
		Arc::new(validator.clone()),
		Arc::new(rpc_author),
		authority.clone(),
	);

	let mut aura = Aura::<_, _, SB, _, _>::new(authority, ocall_api.clone(), env)
		.with_claim_strategy(SlotClaimStrategy::Always);

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
pub struct BlockImporter<A, PB, SB, O, ST> {
	_phantom: PhantomData<(A, PB, SB, ST, O)>,
}

impl<A, PB, SB, O, ST> Default for BlockImporter<A, PB, SB, O, ST> {
	fn default() -> Self {
		Self { _phantom: Default::default() }
	}
}

impl<A, PB, SB, O> BlockImport<PB, SB>
	for BlockImporter<A, PB, SB, O, SidechainDB<SB::Block, SgxExternalities>>
where
	A: Pair,
	A::Public: std::fmt::Debug,
	PB: Block<Hash = H256>,
	SB: SignedBlock<Public = A::Public> + 'static,
	SB::Block: SidechainBlockT<ShardIdentifier = H256>,
	O: ValidateerFetch + GetStorageVerified + Send + Sync,
{
	type Verifier = AuraVerifier<A, PB, SB, SidechainDB<SB::Block, SgxExternalities>, O>;
	type SidechainState = SidechainDB<SB::Block, SgxExternalities>;
	type StateCrypto = Aes;
	type Context = O;

	fn verifier(&self, state: Self::SidechainState) -> Self::Verifier {
		AuraVerifier::<A, PB, _, _, _>::new(SLOT_DURATION, state)
	}

	fn get_state(
		&self,
		shard: &ShardIdentifierFor<SB>,
	) -> Result<Self::SidechainState, ConsensusError> {
		Ok(SidechainDB::<SB::Block, _>::new(
			load(&shard).map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?,
		))
	}

	fn set_state(
		&mut self,
		state: Self::SidechainState,
		shard: &ShardIdentifierFor<SB>,
	) -> Result<(), ConsensusError> {
		crate::state::write(state.ext, shard)
			.map_err(|e| ConsensusError::Other(format!("{:?}", e).into()))?;

		Ok(())
	}

	fn state_key() -> Result<Self::StateCrypto, ConsensusError> {
		AesSeal::unseal()
			.map_err(|e| ConsensusError::Other(format!("Could not unseal: {:?}", e).into()))
	}
}
