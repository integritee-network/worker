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
	traits::{StatePostProcessing, StateUpdateProposer, StfUpdateState},
	BatchExecutionResult, ExecutedOperation,
};
use codec::{Decode, Encode};
use itp_enclave_metrics::EnclaveMetric;
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveMetricsOCallApi, EnclaveOnChainOCallApi};
use itp_pallet_storage::{EnclaveBridgeStorage, EnclaveBridgeStorageKeys};
use itp_sgx_externalities::{SgxExternalitiesTrait, StateHash};
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInstancesInterface,
	prefix_storage_keys_for_parentchain_mirror, StateCallInterface, StateGetterInterface,
	UpdateState,
};
use itp_stf_primitives::{
	error::StfError,
	traits::{GetDecimals, TrustedCallVerification},
	types::{ShardIdentifier, TrustedOperation, TrustedOperationOrHash},
};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_storage::keys::storage_value_key;
use itp_time_utils::{duration_now, now_as_millis};
use itp_types::{
	parentchain::{BlockNumber, Header as ParentchainHeader, ParentchainCall, ParentchainId},
	storage::StorageEntryVerified,
	Balance, ShardConfig, UpgradableShardConfig, H256,
};
use log::*;
use sp_runtime::{traits::Header as HeaderTrait, SaturatedConversion};
use std::{
	collections::BTreeMap, fmt::Debug, marker::PhantomData, sync::Arc, time::Duration, vec,
	vec::Vec,
};

pub struct StfExecutor<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
where
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync,
{
	ocall_api: Arc<OCallApi>,
	state_handler: Arc<StateHandler>,
	node_metadata_repo: Arc<NodeMetadataRepository>,
	_phantom: PhantomData<(Stf, TCS, G)>,
}

impl<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
	StfExecutor<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + EnclaveMetricsOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
	Stf: UpdateState<
			StateHandler::StateT,
			<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
		> + StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)> + From<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
	<Stf as StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>>::Error: Debug,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync,
{
	pub fn new(
		ocall_api: Arc<OCallApi>,
		state_handler: Arc<StateHandler>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Self {
		StfExecutor { ocall_api, state_handler, node_metadata_repo, _phantom: PhantomData }
	}

	/// Execute a trusted call on the STF
	///
	/// We distinguish between an error in the execution, which maps to `Err` and
	/// an invalid trusted call, which results in `Ok(ExecutionStatus::Failure)`. The latter
	/// can be used to remove the trusted call from a queue. In the former case we might keep the
	/// trusted call and just re-try the operation.
	fn execute_trusted_call_on_stf<PH>(
		&self,
		state: &mut StateHandler::StateT,
		trusted_operation: &TrustedOperation<TCS, G>,
		_header: &PH,
		shard: &ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<ExecutedOperation<TCS, G>>
	where
		PH: HeaderTrait<Hash = H256>,
	{
		debug!("query mrenclave of self");
		let mrenclave = self.ocall_api.get_mrenclave_of_self()?;

		let top_or_hash = TrustedOperationOrHash::from_top(trusted_operation.clone());

		let trusted_call = match trusted_operation.to_call().ok_or(Error::InvalidTrustedCallType) {
			Ok(c) => c,
			Err(e) => {
				error!("Error: {:?}", e);
				return Ok(ExecutedOperation::failed(top_or_hash))
			},
		};

		if let false = trusted_call.verify_signature(&mrenclave.m, &shard) {
			error!("TrustedCallSigned: bad signature");
			return Ok(ExecutedOperation::failed(top_or_hash))
		}

		debug!("execute on STF, call with nonce {}", trusted_call.nonce());
		let mut extrinsic_call_backs: Vec<ParentchainCall> = Vec::new();
		if let Err(e) = Stf::execute_call(
			state,
			shard,
			trusted_call.clone(),
			&mut extrinsic_call_backs,
			self.node_metadata_repo.clone(),
		) {
			error!("Stf execute failed: {:?}", e);
			return Ok(ExecutedOperation::failed(top_or_hash))
		}

		let operation_hash = trusted_operation.hash();
		debug!("Operation hash {:?}", operation_hash);

		if let StatePostProcessing::Prune = post_processing {
			state.prune_state_diff();
		}

		for call in extrinsic_call_backs.clone() {
			match call {
				ParentchainCall::Integritee { call, mortality } => trace!(
					"trusted_call wants to send encoded call to [Integritee] parentchain: 0x{} with mortality {:?}",
					hex::encode(call.encode()), mortality
				),
				ParentchainCall::TargetA { call, mortality } => trace!(
					"trusted_call wants to send encoded call to [TargetA] parentchain: 0x{} with mortality {:?}",
					hex::encode(call.encode()), mortality
				),
				ParentchainCall::TargetB { call, mortality } => trace!(
					"trusted_call wants to send encoded call to [TargetB] parentchain: 0x{} with mortality {:?}",
					hex::encode(call.encode()), mortality
				),
			}
		}
		Ok(ExecutedOperation::success(operation_hash, top_or_hash, extrinsic_call_backs))
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
	StfUpdateState<ParentchainHeader, ParentchainId>
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256> + QueryShardState,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
	Stf: UpdateState<
			StateHandler::StateT,
			<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
		> + ParentchainPalletInstancesInterface<
			StateHandler::StateT,
			ParentchainHeader,
			Error = StfError,
		>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		From<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync,
{
	fn update_states(
		&self,
		header: &ParentchainHeader,
		parentchain_id: &ParentchainId,
	) -> Result<()> {
		let shards = self.state_handler.list_shards()?;
		if let Some(shard_id) = shards.get(0) {
			debug!("Update STF storage upon block import!");
			let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard_id)?;
			let storage_hashes =
				Stf::storage_hashes_to_update_on_block(&mut state, parentchain_id, &shard_id);
			trace!(
				"parentchain storage_hash to mirror: 0x{} at header {}",
				hex::encode(storage_hashes[0].clone()),
				header.hash()
			);
			let prefixed_state_diff_update = if let Ok(storage_values) = self
				.ocall_api
				.get_multiple_opaque_storages_verified(storage_hashes, header, parentchain_id)
			{
				trace!("mirror verified storage_values: {:?}", storage_values);
				prefix_storage_keys_for_parentchain_mirror(
					&into_map(storage_values),
					parentchain_id,
				)
			} else {
				error!("mirror parentchain storage upon block import failed");
				Default::default()
			};

			// Update parentchain block data and mirrored state
			match parentchain_id {
				ParentchainId::Integritee =>
					Stf::update_parentchain_integritee_block(&mut state, header.clone()),
				ParentchainId::TargetA =>
					Stf::update_parentchain_target_a_block(&mut state, header.clone()),
				ParentchainId::TargetB =>
					Stf::update_parentchain_target_b_block(&mut state, header.clone()),
			}?;
			// opaque mirroring of state from L1 to L2 (prefixed)
			Stf::apply_state_diff(&mut state, prefixed_state_diff_update.into());
			self.state_handler.write_after_mutation(state, state_lock, &shard_id)?;
		}
		Ok(())
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G> StateUpdateProposer<TCS, G>
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + EnclaveMetricsOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode + StateHash,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesType: Encode,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
	Stf: UpdateState<
			StateHandler::StateT,
			<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
		> + StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>
		+ StateGetterInterface<G, StateHandler::StateT>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		From<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
	<Stf as StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>>::Error: Debug,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + GetDecimals,
{
	type Externalities = StateHandler::StateT;

	fn propose_state_update<PH, F>(
		&self,
		trusted_calls: &[TrustedOperation<TCS, G>],
		header: &PH,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
		prepare_state_function: F,
	) -> Result<BatchExecutionResult<Self::Externalities, TCS, G>>
	where
		PH: HeaderTrait<Hash = H256, Number = BlockNumber>,
		F: FnOnce(Self::Externalities) -> Self::Externalities,
	{
		let started_at = duration_now();
		let ends_at = started_at + max_exec_duration;

		let (state, state_hash_before_execution) = self.state_handler.load_cloned(shard)?;

		// Execute any pre-processing steps. i.e resetting Events from previous block
		let mut state = prepare_state_function(state);
		let mut executed_and_failed_calls = Vec::<ExecutedOperation<TCS, G>>::new();

		let maintenance_mode =
			get_active_shard_config::<StateHandler, Stf, G, PH>(shard, header, &mut state)
				.map_or(false, |shard_config| shard_config.maintenance_mode);

		// i.e. setting timestamp of new block and acting on mirrored state from last imported parentchain block
		Stf::on_initialize(&mut state, shard, *header.number(), now_as_millis()).unwrap_or_else(
			|e| {
				error!("on_initialize failed: {:?}", e);
			},
		);

		// Iterate through all calls until time is over.
		for trusted_call_signed in trusted_calls.into_iter() {
			// Break if allowed time window is over.
			if ends_at < duration_now() {
				info!("stopping execution of further trusted calls because slot time is up");
				break
			}

			match self.execute_trusted_call_on_stf(
				&mut state,
				&trusted_call_signed,
				header,
				shard,
				StatePostProcessing::None,
			) {
				Ok(executed_or_failed_call) => {
					executed_and_failed_calls.push(executed_or_failed_call);
				},
				Err(e) => {
					error!("Failed to attempt call execution: {:?}", e);
				},
			};
		}

		// Execute maintenance tasks if maintenance mode is active
		// This has to execute after the top-pool calls because enclave signer nonce clashes can occur otherwise (e.g. shielding calls).
		// the risk of overdue block production is minimal as all user calls are filtered during maintenance mode anyway
		if maintenance_mode {
			info!("Maintenance mode is active.");
			let mut extrinsic_call_backs: Vec<ParentchainCall> = Vec::new();
			Stf::maintenance_mode_tasks(
				&mut state,
				&shard,
				*header.number(),
				&mut extrinsic_call_backs,
				self.node_metadata_repo.clone(),
			)
			.map_err(|e| error!("maintenance_mode tasks failed: {:?}", e))
			.ok();
			info!(
				"maintenance tasks have triggered {} parentchain calls",
				extrinsic_call_backs.len()
			);
			// we're hacking our unshielding calls into the queue
			executed_and_failed_calls.push(ExecutedOperation::success(
				H256::default(),
				TrustedOperationOrHash::Hash(H256::default()),
				extrinsic_call_backs,
			));
		}

		Stf::on_finalize(&mut state).unwrap_or_else(|e| {
			error!("on_finalize failed: {:?}", e);
		});

		let state_size_bytes = state.size();
		let decimals = state.execute_with(|| G::get_shielding_target_decimals());
		let runtime_metrics = gather_runtime_metrics(&state, decimals);
		let successful_call_count =
			executed_and_failed_calls.iter().filter(|call| call.is_success()).count();
		let failed_call_count = executed_and_failed_calls.len() - successful_call_count;
		self.ocall_api
			.update_metrics(vec![
				EnclaveMetric::StfStateUpdateExecutionDuration(duration_now() - started_at),
				EnclaveMetric::StfStateUpdateExecutedCallsCount(true, successful_call_count as u64),
				EnclaveMetric::StfStateUpdateExecutedCallsCount(false, failed_call_count as u64),
				EnclaveMetric::TopPoolAPrioriSizeSet(trusted_calls.len() as u64),
				EnclaveMetric::StfStateSizeSet(*shard, state_size_bytes as u64),
				EnclaveMetric::StfRuntimeTotalIssuanceSet(runtime_metrics.total_issuance),
				EnclaveMetric::StfRuntimeParentchainProcessedBlockNumberSet(
					ParentchainId::Integritee,
					runtime_metrics.parentchain_integritee_processed_block_number,
				),
				EnclaveMetric::StfRuntimeParentchainProcessedBlockNumberSet(
					ParentchainId::TargetA,
					runtime_metrics.parentchain_target_a_processed_block_number,
				),
				EnclaveMetric::StfRuntimeParentchainProcessedBlockNumberSet(
					ParentchainId::TargetB,
					runtime_metrics.parentchain_target_b_processed_block_number,
				),
			])
			.unwrap_or_else(|e| error!("failed to update prometheus metric: {:?}", e));
		Ok(BatchExecutionResult {
			executed_operations: executed_and_failed_calls,
			state_hash_before_execution,
			state_after_execution: state,
		})
	}
}

fn into_map(
	storage_entries: Vec<StorageEntryVerified<Vec<u8>>>,
) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
	storage_entries.into_iter().map(|e| e.into_tuple()).collect()
}

// todo: we need to clarify where these functions belong and if we need them at all. moved them from ita-stf but we can no longer depend on that
pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
	Vec::new()
}

fn get_active_shard_config<StateHandler, Stf, G, PH>(
	shard: &ShardIdentifier,
	header: &PH,
	state: &mut <StateHandler as HandleState>::StateT,
) -> Option<ShardConfig>
where
	Stf: UpdateState<
			StateHandler::StateT,
			<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
		> + StateGetterInterface<G, StateHandler::StateT>,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + GetDecimals,
	PH: HeaderTrait<Hash = H256, Number = BlockNumber>,
{
	Stf::get_parentchain_mirror_state::<UpgradableShardConfig>(
		state,
		EnclaveBridgeStorage::upgradable_shard_config(*shard),
		&ParentchainId::Integritee,
	)
	.map(|upgradable_shard_config| {
		let actual_shard_config = if let (Some(upgrade_block), Some(pending_upgrade)) =
			(upgradable_shard_config.upgrade_at, upgradable_shard_config.pending_upgrade)
		{
			trace!("pending shard config upgrade at block {}", upgrade_block);
			let due = i32::saturated_from(
				i64::from(*header.number()).saturating_sub(upgrade_block.into()),
			);
			if due >= 0 {
				pending_upgrade
			} else {
				upgradable_shard_config.active_config
			}
		} else {
			upgradable_shard_config.active_config
		};
		trace!("ShardConfig::fingerprint = {}", actual_shard_config.enclave_fingerprint);
		trace!("ShardConfig::maintenance_mode = {}", actual_shard_config.maintenance_mode);
		actual_shard_config
	})
}

/// assumes a common structure of sgx_runtime and extracts interesting metrics
/// while this may not be the best abstraction, it avoids circular dependencies
/// with app-libs and will be suitable in 99% of cases
fn gather_runtime_metrics<State>(state: &State, decimals: u8) -> RuntimeMetrics
where
	State: SgxExternalitiesTrait + Encode,
{
	// prometheus has no support for NaN, therefore we fall back to -1
	let total_issuance: f64 = state
		.get(&storage_value_key("Balances", "TotalIssuance"))
		.map(|v| {
			Balance::decode(&mut v.as_slice())
				.map(|b| (b as f64) / 10f64.powi(decimals as i32))
				.unwrap_or(-1.0)
		})
		.unwrap_or(-1.0);
	// fallback to zero is fine here
	let parentchain_integritee_processed_block_number: u32 = state
		.get(&storage_value_key("ParentchainIntegritee", "Number"))
		.map(|v| BlockNumber::decode(&mut v.as_slice()).unwrap_or_default())
		.unwrap_or_default();
	let parentchain_target_a_processed_block_number: u32 = state
		.get(&storage_value_key("ParentchainTargetA", "Number"))
		.map(|v| BlockNumber::decode(&mut v.as_slice()).unwrap_or_default())
		.unwrap_or_default();
	let parentchain_target_b_processed_block_number: u32 = state
		.get(&storage_value_key("ParentchainTargetB", "Number"))
		.map(|v| BlockNumber::decode(&mut v.as_slice()).unwrap_or_default())
		.unwrap_or_default();
	RuntimeMetrics {
		total_issuance,
		parentchain_integritee_processed_block_number,
		parentchain_target_a_processed_block_number,
		parentchain_target_b_processed_block_number,
	}
}

struct RuntimeMetrics {
	total_issuance: f64,
	parentchain_integritee_processed_block_number: u32,
	parentchain_target_a_processed_block_number: u32,
	parentchain_target_b_processed_block_number: u32,
}
