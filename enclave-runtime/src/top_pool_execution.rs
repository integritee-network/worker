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
	error::Result,
	global_components::{
		GLOBAL_EXTRINSICS_FACTORY_COMPONENT, GLOBAL_OCALL_API_COMPONENT,
		GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_STF_EXECUTOR_COMPONENT,
		GLOBAL_TOP_POOL_AUTHOR_COMPONENT, GLOBAL_TRIGGERED_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT,
	},
	sync::{EnclaveLock, EnclaveStateRWLock},
};
use codec::Encode;
use itc_parentchain::{
	block_import_dispatcher::triggered_dispatcher::TriggerParentchainBlockImport,
	light_client::{
		concurrent_access::ValidatorAccess, BlockNumberOps, ExtrinsicSender, LightClientState,
		NumberFor,
	},
};
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_ocall_api::{EnclaveOnChainOCallApi, EnclaveSidechainOCallApi};
use itp_settings::sidechain::SLOT_DURATION;
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use itp_time_utils::duration_now;
use itp_types::{Block, OpaqueCall, H256};
use its_primitives::{
	traits::{
		Block as SidechainBlockTrait, Header as HeaderTrait, ShardIdentifierFor, SignedBlock,
	},
	types::block::SignedBlock as SignedSidechainBlock,
};
use its_sidechain::{
	aura::{proposer_factory::ProposerFactory, Aura, SlotClaimStrategy},
	consensus_common::{Environment, Error as ConsensusError, ProcessBlockImportQueue},
	slots::{sgx::LastSlotSeal, yield_next_slot, PerShardSlotWorkerScheduler, SlotInfo},
	validateer_fetch::ValidateerFetch,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::Pair;
use sp_runtime::{
	generic::SignedBlock as SignedParentchainBlock, traits::Block as BlockTrait, MultiSignature,
};
use std::{sync::Arc, time::Instant, vec::Vec};

#[no_mangle]
pub unsafe extern "C" fn execute_trusted_calls() -> sgx_status_t {
	if let Err(e) = execute_top_pool_trusted_calls_internal() {
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
/// *   Import all pending parentchain blocks.
/// *   Sends sidechain `confirm_block` xt's with the produced sidechain blocks.
/// *   Broadcast produced sidechain blocks to peer validateers.
fn execute_top_pool_trusted_calls_internal() -> Result<()> {
	let start_time = Instant::now();

	// We acquire lock explicitly (variable binding), since '_' will drop the lock after the statement.
	// See https://medium.com/codechain/rust-underscore-does-not-bind-fec6a18115a8
	let _enclave_write_lock = EnclaveLock::write_all()?;

	let slot_beginning_timestamp = duration_now();

	let parentchain_import_dispatcher =
		GLOBAL_TRIGGERED_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT.get()?;

	let validator_access = GLOBAL_PARENTCHAIN_BLOCK_VALIDATOR_ACCESS_COMPONENT.get()?;

	// This gets the latest imported block. We accept that all of AURA, up until the block production
	// itself, will  operate on a parentchain block that is potentially outdated by one block
	// (in case we have a block in the queue, but not imported yet).
	let current_parentchain_header = validator_access.execute_on_validator(|v| {
		let latest_parentchain_header = v.latest_finalized_header(v.num_relays())?;
		Ok(latest_parentchain_header)
	})?;

	// Import any sidechain blocks that are in the import queue. In case we are missing blocks,
	// a peer sync will happen. If that happens, the slot time might already be used up just by this import.
	let sidechain_block_import_queue_worker =
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT.get()?;

	let sidechain_block_queue_start = Instant::now();

	let latest_parentchain_header =
		sidechain_block_import_queue_worker.process_queue(&current_parentchain_header)?;

	info!(
		"Elapsed time to process sidechain block import queue: {} ms",
		sidechain_block_queue_start.elapsed().as_millis()
	);

	let stf_executor = GLOBAL_STF_EXECUTOR_COMPONENT.get()?;

	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let block_composer = GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT.get()?;

	let extrinsics_factory = GLOBAL_EXTRINSICS_FACTORY_COMPONENT.get()?;

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let authority = Ed25519Seal::unseal_from_static_file()?;

	info!("Elapsed time before AURA execution: {} ms", start_time.elapsed().as_millis());

	match yield_next_slot(
		slot_beginning_timestamp,
		SLOT_DURATION,
		latest_parentchain_header,
		&mut LastSlotSeal,
	)? {
		Some(slot) => {
			let remaining_time = slot.ends_at - slot.timestamp;
			info!(
				"Remaining slot time for aura: {} ms, {}% of slot time",
				remaining_time.as_millis(),
				(remaining_time.as_millis() as f64 / slot.duration.as_millis() as f64) * 100f64
			);

			let shards = state_handler.list_shards()?;
			let env = ProposerFactory::<Block, _, _, _>::new(
				top_pool_author,
				stf_executor,
				block_composer,
			);

			let (blocks, opaque_calls) = exec_aura_on_slot::<_, _, SignedSidechainBlock, _, _, _>(
				slot,
				authority,
				ocall_api.clone(),
				parentchain_import_dispatcher,
				env,
				shards,
			)?;

			debug!("Aura executed successfully");

			// Drop lock as soon as we don't need it anymore.
			drop(_enclave_write_lock);

			send_blocks_and_extrinsics::<Block, _, _, _, _>(
				blocks,
				opaque_calls,
				ocall_api,
				validator_access.as_ref(),
				extrinsics_factory.as_ref(),
			)?
		},
		None => {
			debug!("No slot yielded. Skipping block production.");
			return Ok(())
		},
	};

	debug!("End sidechain block production cycle");
	Ok(())
}

/// Executes aura for the given `slot`.
pub(crate) fn exec_aura_on_slot<
	Authority,
	ParentchainBlock,
	SignedSidechainBlock,
	OCallApi,
	PEnvironment,
	BlockImportTrigger,
>(
	slot: SlotInfo<ParentchainBlock>,
	authority: Authority,
	ocall_api: Arc<OCallApi>,
	block_import_trigger: Arc<BlockImportTrigger>,
	proposer_environment: PEnvironment,
	shards: Vec<ShardIdentifierFor<SignedSidechainBlock>>,
) -> Result<(Vec<SignedSidechainBlock>, Vec<OpaqueCall>)>
where
	ParentchainBlock: BlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedBlock<Public = Authority::Public, Signature = MultiSignature> + 'static, // Setting the public type is necessary due to some non-generic downstream code.
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = Authority::Public>,
	<<SignedSidechainBlock as SignedBlock>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	SignedSidechainBlock::Signature: From<Authority::Signature>,
	Authority: Pair<Public = sp_core::ed25519::Public>,
	Authority::Public: Encode,
	OCallApi: ValidateerFetch + EnclaveOnChainOCallApi + Send + 'static,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	PEnvironment:
		Environment<ParentchainBlock, SignedSidechainBlock, Error = ConsensusError> + Send + Sync,
	BlockImportTrigger: TriggerParentchainBlockImport<SignedParentchainBlock<ParentchainBlock>>,
{
	debug!("[Aura] Executing aura for slot: {:?}", slot);

	let mut aura = Aura::<_, ParentchainBlock, SignedSidechainBlock, PEnvironment, _, _>::new(
		authority,
		ocall_api.as_ref().clone(),
		block_import_trigger,
		proposer_environment,
	)
	.with_claim_strategy(SlotClaimStrategy::RoundRobin)
	.with_allow_delayed_proposal(false);

	let (blocks, xts): (Vec<_>, Vec<_>) =
		PerShardSlotWorkerScheduler::on_slot(&mut aura, slot, shards)
			.into_iter()
			.map(|r| (r.block, r.parentchain_effects))
			.unzip();

	let opaque_calls: Vec<OpaqueCall> = xts.into_iter().flatten().collect();
	Ok((blocks, opaque_calls))
}

/// Broadcasts sidechain blocks to fellow peers and sends opaque calls as extrinsic to the parentchain.
pub(crate) fn send_blocks_and_extrinsics<
	ParentchainBlock,
	SignedSidechainBlock,
	OCallApi,
	ValidatorAccessor,
	ExtrinsicsFactory,
>(
	blocks: Vec<SignedSidechainBlock>,
	opaque_calls: Vec<OpaqueCall>,
	ocall_api: Arc<OCallApi>,
	validator_access: &ValidatorAccessor,
	extrinsics_factory: &ExtrinsicsFactory,
) -> Result<()>
where
	ParentchainBlock: BlockTrait,
	SignedSidechainBlock: SignedBlock + 'static,
	OCallApi: EnclaveSidechainOCallApi,
	ValidatorAccessor: ValidatorAccess<ParentchainBlock> + Send + Sync + 'static,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	ExtrinsicsFactory: CreateExtrinsics,
{
	debug!("Proposing {} sidechain block(s) (broadcasting to peers)", blocks.len());
	ocall_api.propose_sidechain_blocks(blocks)?;

	let xts = extrinsics_factory.create_extrinsics(opaque_calls.as_slice(), None)?;

	debug!("Sending sidechain block(s) confirmation extrinsic.. ");
	validator_access.execute_mut_on_validator(|v| v.send_extrinsics(xts))?;

	Ok(())
}
