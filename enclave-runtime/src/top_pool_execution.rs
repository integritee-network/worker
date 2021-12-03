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

use crate::{
	error::{Error, Result},
	ocall::OcallApi,
	sync::{EnclaveLock, EnclaveStateRWLock},
};
use codec::Encode;
use itc_parentchain::light_client::{
	concurrent_access::ValidatorAccess, BlockNumberOps, LightClientState, NumberFor, Validator,
	ValidatorAccessor,
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::{CreateExtrinsics, ExtrinsicsFactory};
use itp_nonce_cache::GLOBAL_NONCE_CACHE;
use itp_ocall_api::{EnclaveOnChainOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::{AesSeal, Ed25519Seal};
use itp_sgx_io::SealedIO;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::{query_shard_state::QueryShardState, GlobalFileStateHandler};
use itp_time_utils::{duration_now, remaining_time};
use itp_types::{Block, OpaqueCall, H256};
use its_sidechain::{
	aura::{proposer_factory::ProposerFactory, Aura, SlotClaimStrategy},
	block_composer::BlockComposer,
	consensus_common::{Environment, Error as ConsensusError},
	primitives::{
		traits::{Block as SidechainBlockT, ShardIdentifierFor, SignedBlock},
		types::block::SignedBlock as SignedSidechainBlock,
	},
	slots::{sgx::LastSlotSeal, yield_next_slot, PerShardSlotWorkerScheduler, SlotInfo},
	top_pool_executor::{TopPoolGetterOperator, TopPoolOperationHandler},
	top_pool_rpc_author::global_author_container::GLOBAL_RPC_AUTHOR_COMPONENT,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::Pair;
use sp_runtime::{traits::Block as BlockTrait, MultiSignature};
use std::{sync::Arc, vec::Vec};

#[no_mangle]
pub unsafe extern "C" fn execute_trusted_getters() -> sgx_status_t {
	if let Err(e) = execute_top_pool_trusted_getters_on_all_shards() {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`execute_trusted_getters`] function to be able to use the `?` operator.
///
/// Executes trusted getters for a scheduled amount of time (defined by settings).
fn execute_top_pool_trusted_getters_on_all_shards() -> Result<()> {
	use itp_settings::enclave::MAX_TRUSTED_GETTERS_EXEC_DURATION;

	let rpc_author = GLOBAL_RPC_AUTHOR_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve author mutex. It might not be initialized?");
		Error::MutexAccess
	})?;

	let state_handler = Arc::new(GlobalFileStateHandler);
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));

	let shards = state_handler.list_shards()?;
	let mut remaining_shards = shards.len() as u32;
	let ends_at = duration_now() + MAX_TRUSTED_GETTERS_EXEC_DURATION;

	let top_pool_executor =
		TopPoolOperationHandler::<Block, SignedSidechainBlock, _, _>::new(rpc_author, stf_executor);

	// Execute trusted getters for each shard. Each shard gets equal amount of time to execute
	// getters.
	for shard in shards.into_iter() {
		let shard_exec_time = match remaining_time(ends_at)
			.map(|r| r.checked_div(remaining_shards))
			.flatten()
		{
			Some(t) => t,
			None => {
				info!("[Enclave] Could not execute trusted operations for all shards. Remaining number of shards: {}.", remaining_shards);
				break
			},
		};

		match top_pool_executor.execute_trusted_getters_on_shard(&shard, shard_exec_time) {
			Ok(()) => {},
			Err(e) => error!("Error in trusted getter execution for shard {:?}: {:?}", shard, e),
		}

		remaining_shards -= 1;
	}

	Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn execute_trusted_calls() -> sgx_status_t {
	if let Err(e) = execute_top_pool_trusted_calls_internal::<Block>() {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`execute_trusted_calls`] function to be able to use the `?` operator.
///
/// Executes `Aura::on_slot() for `slot` if it is this enclave's `Slot`.
///
/// This function makes an ocall that does the following:
///
/// *   sends sidechain `confirm_block` xt's with the produced sidechain blocks
/// *   gossip produced sidechain blocks to peer validateers.
fn execute_top_pool_trusted_calls_internal<PB>() -> Result<()>
where
	PB: BlockTrait<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
{
	// we acquire lock explicitly (variable binding), since '_' will drop the lock after the statement
	// see https://medium.com/codechain/rust-underscore-does-not-bind-fec6a18115a8
	let _enclave_write_lock = EnclaveLock::write_all()?;

	let validator_access = ValidatorAccessor::<PB>::default();

	let (latest_parentchain_header, genesis_hash) = validator_access.execute_on_validator(|v| {
		let latest_parentchain_header = v.latest_finalized_header(v.num_relays())?;
		let genesis_hash = v.genesis_hash(v.num_relays())?;
		Ok((latest_parentchain_header, genesis_hash))
	})?;

	let authority = Ed25519Seal::unseal()?;
	let state_key = AesSeal::unseal()?;

	let rpc_author = GLOBAL_RPC_AUTHOR_COMPONENT.get().ok_or_else(|| {
		error!("Failed to retrieve author mutex. Maybe it's not initialized?");
		Error::MutexAccess
	})?;

	let state_handler = Arc::new(GlobalFileStateHandler);
	let stf_executor = Arc::new(StfExecutor::new(Arc::new(OcallApi), state_handler.clone()));
	let extrinsics_factory =
		ExtrinsicsFactory::new(genesis_hash, authority.clone(), GLOBAL_NONCE_CACHE.clone());

	let top_pool_executor =
		Arc::new(TopPoolOperationHandler::<PB, SignedSidechainBlock, _, _>::new(
			rpc_author.clone(),
			stf_executor.clone(),
		));

	let block_composer = Arc::new(BlockComposer::new(authority.clone(), state_key, rpc_author));

	match yield_next_slot(
		duration_now(),
		SLOT_DURATION,
		latest_parentchain_header,
		&mut LastSlotSeal,
	)? {
		Some(slot) => {
			let shards = state_handler.list_shards()?;
			let env = ProposerFactory::new(top_pool_executor, stf_executor, block_composer);

			let (blocks, opaque_calls) = exec_aura_on_slot::<_, _, SignedSidechainBlock, _, _>(
				slot, authority, OcallApi, env, shards,
			)?;
			// Drop lock as soon as we don't need it anymore.
			drop(_enclave_write_lock);
			send_blocks_and_extrinsics::<PB, _, _, _, _>(
				blocks,
				opaque_calls,
				OcallApi,
				&validator_access,
				&extrinsics_factory,
			)?
		},
		None => {
			debug!("No slot yielded. Skipping block production.");
			return Ok(())
		},
	};

	Ok(())
}

/// Executes aura for the given `slot`.
fn exec_aura_on_slot<Authority, PB, SB, OCallApi, PEnvironment>(
	slot: SlotInfo<PB>,
	authority: Authority,
	ocall_api: OCallApi,
	proposer_environment: PEnvironment,
	shards: Vec<ShardIdentifierFor<SB>>,
) -> Result<(Vec<SB>, Vec<OpaqueCall>)>
where
	PB: BlockTrait<Hash = H256>,
	SB: SignedBlock<Public = Authority::Public, Signature = MultiSignature> + 'static, // Setting the public type is necessary due to some non-generic downstream code.
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = Authority::Public>,
	SB::Signature: From<Authority::Signature>,
	Authority: Pair<Public = sp_core::ed25519::Public>,
	Authority::Public: Encode,
	OCallApi: EnclaveOnChainOCallApi + 'static,
	NumberFor<PB>: BlockNumberOps,
	PEnvironment: Environment<PB, SB, Error = ConsensusError> + Send + Sync,
{
	log::info!("[Aura] Executing aura for slot: {:?}", slot);

	let mut aura =
		Aura::<_, _, SB, PEnvironment, _>::new(authority, ocall_api, proposer_environment)
			.with_claim_strategy(SlotClaimStrategy::Always)
			.with_allow_delayed_proposal(true);

	let (blocks, xts): (Vec<_>, Vec<_>) =
		PerShardSlotWorkerScheduler::on_slot(&mut aura, slot, shards)
			.into_iter()
			.map(|r| (r.block, r.parentchain_effects))
			.unzip();

	let opaque_calls: Vec<OpaqueCall> = xts.into_iter().flatten().collect();
	Ok((blocks, opaque_calls))
}

/// Gossips sidechain blocks to fellow peers and sends opaque calls as extrinsic to the parentchain.
fn send_blocks_and_extrinsics<PB, SB, OCallApi, ValidatorAccessor, ExtrinsicsFactory>(
	blocks: Vec<SB>,
	opaque_calls: Vec<OpaqueCall>,
	ocall_api: OCallApi,
	validator_access: &ValidatorAccessor,
	extrinsics_factory: &ExtrinsicsFactory,
) -> Result<()>
where
	PB: BlockTrait,
	SB: SignedBlock + 'static,
	OCallApi: EnclaveSidechainOCallApi + EnclaveOnChainOCallApi,
	ValidatorAccessor: ValidatorAccess<PB> + Clone + Send + Sync + 'static,
	NumberFor<PB>: BlockNumberOps,
	ExtrinsicsFactory: CreateExtrinsics,
{
	ocall_api.propose_sidechain_blocks(blocks)?;

	let xts = extrinsics_factory.create_extrinsics(opaque_calls.as_slice())?;

	validator_access.execute_mut_on_validator(|v| v.send_extrinsics(&ocall_api, xts))?;
	Ok(())
}
