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
	initialization::global_components::{
		GLOBAL_OCALL_API_COMPONENT, GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_TOP_POOL_AUTHOR_COMPONENT,
	},
	sync::{EnclaveLock, EnclaveStateRWLock},
	utils::{
		get_extrinsic_factory_from_integritee_solo_or_parachain,
		get_extrinsic_factory_from_target_a_solo_or_parachain,
		get_extrinsic_factory_from_target_b_solo_or_parachain,
		get_stf_executor_from_solo_or_parachain,
		get_triggered_dispatcher_from_integritee_solo_or_parachain,
		get_triggered_dispatcher_from_target_a_solo_or_parachain,
		get_triggered_dispatcher_from_target_b_solo_or_parachain,
		get_validator_accessor_from_integritee_solo_or_parachain,
		get_validator_accessor_from_target_a_solo_or_parachain,
		get_validator_accessor_from_target_b_solo_or_parachain,
	},
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
use itp_sgx_crypto::key_repository::AccessKey;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use itp_time_utils::duration_now;
use itp_types::{parentchain::ParentchainCall, Block, OpaqueCall, H256};
use its_primitives::{
	traits::{
		Block as SidechainBlockTrait, Header as HeaderTrait, ShardIdentifierFor, SignedBlock,
	},
	types::block::SignedBlock as SignedSidechainBlock,
};
use its_sidechain::{
	aura::{proposer_factory::ProposerFactory, Aura, SlotClaimStrategy},
	consensus_common::{Environment, Error as ConsensusError, ProcessBlockImportQueue},
	slots::{yield_next_slot, LastSlot, PerShardSlotWorkerScheduler, SlotInfo},
	validateer_fetch::ValidateerFetch,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::{crypto::UncheckedFrom, Pair};
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

	let integritee_parentchain_import_dispatcher =
		get_triggered_dispatcher_from_integritee_solo_or_parachain()?;
	let maybe_target_a_parentchain_import_dispatcher =
		get_triggered_dispatcher_from_target_a_solo_or_parachain().ok();
	let maybe_target_b_parentchain_import_dispatcher =
		get_triggered_dispatcher_from_target_b_solo_or_parachain().ok();

	let maybe_latest_target_a_parentchain_header =
		if let Some(ref _triggered_dispatcher) = maybe_target_a_parentchain_import_dispatcher {
			let validator_access = get_validator_accessor_from_target_a_solo_or_parachain()?;
			Some(validator_access.execute_on_validator(|v| {
				let latest_parentchain_header = v.latest_finalized_header()?;
				Ok(latest_parentchain_header)
			})?)
		} else {
			None
		};

	let maybe_latest_target_b_parentchain_header =
		if let Some(ref _triggered_dispatcher) = maybe_target_b_parentchain_import_dispatcher {
			let validator_access = get_validator_accessor_from_target_b_solo_or_parachain()?;
			Some(validator_access.execute_on_validator(|v| {
				let latest_parentchain_header = v.latest_finalized_header()?;
				Ok(latest_parentchain_header)
			})?)
		} else {
			None
		};

	let integritee_validator_access = get_validator_accessor_from_integritee_solo_or_parachain()?;

	// This gets the latest imported block. We accept that all of AURA, up until the block production
	// itself, will  operate on a parentchain block that is potentially outdated by one block
	// (in case we have a block in the queue, but not imported yet).
	let current_integritee_parentchain_header =
		integritee_validator_access.execute_on_validator(|v| {
			let latest_parentchain_header = v.latest_finalized_header()?;
			Ok(latest_parentchain_header)
		})?;

	// Import any sidechain blocks that are in the import queue. In case we are missing blocks,
	// a peer sync will happen. If that happens, the slot time might already be used up just by this import.
	let sidechain_block_import_queue_worker =
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT.get()?;

	let latest_integritee_parentchain_header = sidechain_block_import_queue_worker
		.process_queue(&current_integritee_parentchain_header)?;

	trace!(
		"Elapsed time to process sidechain block import queue: {} ms",
		start_time.elapsed().as_millis()
	);

	let stf_executor = get_stf_executor_from_solo_or_parachain()?;

	let top_pool_author = GLOBAL_TOP_POOL_AUTHOR_COMPONENT.get()?;

	let block_composer = GLOBAL_SIDECHAIN_BLOCK_COMPOSER_COMPONENT.get()?;

	let state_handler = GLOBAL_STATE_HANDLER_COMPONENT.get()?;

	let ocall_api = GLOBAL_OCALL_API_COMPONENT.get()?;

	let authority = GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get()?.retrieve_key()?;

	match yield_next_slot(
		slot_beginning_timestamp,
		SLOT_DURATION,
		latest_integritee_parentchain_header,
		maybe_latest_target_a_parentchain_header,
		maybe_latest_target_b_parentchain_header,
		&mut LastSlot,
	)? {
		Some(slot) => {
			if slot.duration_remaining().is_none() {
				warn!("No time remaining in slot, skipping AURA execution");
				return Ok(())
			}

			log_remaining_slot_duration(&slot, "Before AURA");

			let shards = state_handler.list_shards()?;
			let env = ProposerFactory::<Block, _, _, _>::new(
				top_pool_author,
				stf_executor,
				block_composer,
			);

			let (blocks, parentchain_calls) =
				exec_aura_on_slot::<_, _, SignedSidechainBlock, _, _, _, _, _>(
					slot.clone(),
					authority,
					ocall_api.clone(),
					integritee_parentchain_import_dispatcher,
					maybe_target_a_parentchain_import_dispatcher,
					maybe_target_b_parentchain_import_dispatcher,
					env,
					shards,
				)?;

			debug!("Aura executed successfully");

			// Drop lock as soon as we don't need it anymore.
			drop(_enclave_write_lock);

			log_remaining_slot_duration(&slot, "After AURA");

			send_blocks_and_extrinsics::<Block, _, _>(blocks, parentchain_calls, ocall_api)?;

			log_remaining_slot_duration(&slot, "After broadcasting and sending extrinsic");
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn exec_aura_on_slot<
	Authority,
	ParentchainBlock,
	SignedSidechainBlock,
	OCallApi,
	PEnvironment,
	IntegriteeBlockImportTrigger,
	TargetABlockImportTrigger,
	TargetBBlockImportTrigger,
>(
	slot: SlotInfo<ParentchainBlock>,
	authority: Authority,
	ocall_api: Arc<OCallApi>,
	integritee_block_import_trigger: Arc<IntegriteeBlockImportTrigger>,
	maybe_target_a_block_import_trigger: Option<Arc<TargetABlockImportTrigger>>,
	maybe_target_b_block_import_trigger: Option<Arc<TargetBBlockImportTrigger>>,
	proposer_environment: PEnvironment,
	shards: Vec<ShardIdentifierFor<SignedSidechainBlock>>,
) -> Result<(Vec<SignedSidechainBlock>, Vec<ParentchainCall>)>
where
	ParentchainBlock: BlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedBlock<Public = Authority::Public, Signature = MultiSignature> + 'static, // Setting the public type is necessary due to some non-generic downstream code.
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = Authority::Public>,
	<<SignedSidechainBlock as SignedBlock>::Block as SidechainBlockTrait>::HeaderType:
		HeaderTrait<ShardIdentifier = H256>,
	SignedSidechainBlock::Signature: From<Authority::Signature>,
	Authority: Pair<Public = sp_core::ed25519::Public>,
	Authority::Public: Encode + UncheckedFrom<[u8; 32]>,
	OCallApi: ValidateerFetch + EnclaveOnChainOCallApi + Send + 'static,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	PEnvironment:
		Environment<ParentchainBlock, SignedSidechainBlock, Error = ConsensusError> + Send + Sync,
	IntegriteeBlockImportTrigger:
		TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>,
	TargetABlockImportTrigger:
		TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>,
	TargetBBlockImportTrigger:
		TriggerParentchainBlockImport<SignedBlockType = SignedParentchainBlock<ParentchainBlock>>,
{
	debug!("[Aura] Executing aura for slot: {:?}", slot);

	let mut aura =
		Aura::<_, ParentchainBlock, SignedSidechainBlock, PEnvironment, _, _, _, _>::new(
			authority,
			ocall_api.as_ref().clone(),
			integritee_block_import_trigger,
			maybe_target_a_block_import_trigger,
			maybe_target_b_block_import_trigger,
			proposer_environment,
		)
		.with_claim_strategy(SlotClaimStrategy::RoundRobin);

	let (blocks, pxts): (Vec<_>, Vec<_>) =
		PerShardSlotWorkerScheduler::on_slot(&mut aura, slot, shards)
			.into_iter()
			.map(|r| (r.block, r.parentchain_effects))
			.unzip();

	let opaque_calls: Vec<ParentchainCall> = pxts.into_iter().flatten().collect();
	Ok((blocks, opaque_calls))
}

/// Broadcasts sidechain blocks to fellow peers and sends opaque calls as extrinsic to the parentchain.
pub(crate) fn send_blocks_and_extrinsics<ParentchainBlock, SignedSidechainBlock, OCallApi>(
	blocks: Vec<SignedSidechainBlock>,
	parentchain_calls: Vec<ParentchainCall>,
	ocall_api: Arc<OCallApi>,
) -> Result<()>
where
	ParentchainBlock: BlockTrait,
	SignedSidechainBlock: SignedBlock + 'static,
	OCallApi: EnclaveSidechainOCallApi,
	NumberFor<ParentchainBlock>: BlockNumberOps,
{
	debug!("Proposing {} sidechain block(s) (broadcasting to peers)", blocks.len());
	ocall_api.propose_sidechain_blocks(blocks)?;

	let calls: Vec<OpaqueCall> = parentchain_calls
		.iter()
		.filter_map(|parentchain_call| parentchain_call.as_integritee())
		.collect();
	debug!("Enclave wants to send {} extrinsics to Integritee Parentchain", calls.len());
	if !calls.is_empty() {
		let extrinsics_factory = get_extrinsic_factory_from_integritee_solo_or_parachain()?;
		let xts = extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;
		let validator_access = get_validator_accessor_from_integritee_solo_or_parachain()?;
		validator_access.execute_mut_on_validator(|v| v.send_extrinsics(xts))?;
	}
	let calls: Vec<OpaqueCall> = parentchain_calls
		.iter()
		.filter_map(|parentchain_call| parentchain_call.as_target_a())
		.collect();
	debug!("Enclave wants to send {} extrinsics to TargetA Parentchain", calls.len());
	if !calls.is_empty() {
		let extrinsics_factory = get_extrinsic_factory_from_target_a_solo_or_parachain()?;
		let xts = extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;
		let validator_access = get_validator_accessor_from_target_a_solo_or_parachain()?;
		validator_access.execute_mut_on_validator(|v| v.send_extrinsics(xts))?;
	}
	let calls: Vec<OpaqueCall> = parentchain_calls
		.iter()
		.filter_map(|parentchain_call| parentchain_call.as_target_b())
		.collect();
	debug!("Enclave wants to send {} extrinsics to TargetB Parentchain", calls.len());
	if !calls.is_empty() {
		let extrinsics_factory = get_extrinsic_factory_from_target_b_solo_or_parachain()?;
		let xts = extrinsics_factory.create_extrinsics(calls.as_slice(), None)?;
		let validator_access = get_validator_accessor_from_target_b_solo_or_parachain()?;
		validator_access.execute_mut_on_validator(|v| v.send_extrinsics(xts))?;
	}

	Ok(())
}

fn log_remaining_slot_duration<B: BlockTrait<Hash = H256>>(
	slot_info: &SlotInfo<B>,
	stage_name: &str,
) {
	match slot_info.duration_remaining() {
		None => {
			info!("No time remaining in slot (id: {:?}, stage: {})", slot_info.slot, stage_name);
		},
		Some(remainder) => {
			trace!(
				"Remaining time in slot (id: {:?}, stage {}): {} ms, {}% of slot time",
				slot_info.slot,
				stage_name,
				remainder.as_millis(),
				(remainder.as_millis() as f64 / slot_info.duration.as_millis() as f64) * 100f64
			);
		},
	};
}
