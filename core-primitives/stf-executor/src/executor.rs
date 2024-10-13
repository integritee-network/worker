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
use itp_sgx_externalities::{SgxExternalitiesTrait, StateHash};
use itp_stf_interface::{
	parentchain_pallet::ParentchainPalletInstancesInterface, StateCallInterface, UpdateState,
};
use itp_stf_primitives::{
	traits::TrustedCallVerification,
	types::{ShardIdentifier, TrustedOperation, TrustedOperationOrHash},
};
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_time_utils::{duration_now, now_as_millis};
use itp_types::{
	parentchain::{Header as ParentchainHeader, ParentchainCall, ParentchainId},
	storage::StorageEntryVerified,
	H256,
};
use log::*;
use sp_runtime::traits::Header as HeaderTrait;
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
				ParentchainCall::Integritee(opaque_call) => trace!(
					"trusted_call wants to send encoded call to [Integritee] parentchain: 0x{}",
					hex::encode(opaque_call.encode())
				),
				ParentchainCall::TargetA(opaque_call) => trace!(
					"trusted_call wants to send encoded call to [TargetA] parentchain: 0x{}",
					hex::encode(opaque_call.encode())
				),
				ParentchainCall::TargetB(opaque_call) => trace!(
					"trusted_call wants to send encoded call to [TargetB] parentchain: 0x{}",
					hex::encode(opaque_call.encode())
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
		> + ParentchainPalletInstancesInterface<StateHandler::StateT, ParentchainHeader>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
	<Stf as ParentchainPalletInstancesInterface<StateHandler::StateT, ParentchainHeader>>::Error:
		Debug,
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
		debug!("Update STF storage upon block import!");
		let storage_hashes = Stf::storage_hashes_to_update_on_block(parentchain_id);

		// global requests they are the same for every shard
		let state_diff_update = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header, parentchain_id)
			.map(into_map)?;

		// Update parentchain block on all states.
		// TODO: Investigate if this is still necessary. We load and clone the entire state here,
		// which scales badly for increasing state size.
		let shards = self.state_handler.list_shards()?;
		for shard_id in shards {
			let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard_id)?;
			match Stf::update_parentchain_integritee_block(&mut state, header.clone()) {
				Ok(_) => {
					self.state_handler.write_after_mutation(state, state_lock, &shard_id)?;
				},
				Err(e) => error!("Could not update parentchain block. {:?}: {:?}", shard_id, e),
			}
		}

		if parentchain_id != &ParentchainId::Integritee {
			// nothing else to do
			return Ok(())
		}

		// look for new shards and initialize them
		if let Some(maybe_shards) = state_diff_update.get(&shards_key_hash()) {
			match maybe_shards {
				Some(shards) => self.initialize_new_shards(header, &state_diff_update, &shards)?,
				None => debug!("No shards are on the chain yet"),
			};
		};
		Ok(())
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
	StfExecutor<OCallApi, StateHandler, NodeMetadataRepository, Stf, TCS, G>
where
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		From<BTreeMap<Vec<u8>, Option<Vec<u8>>>> + IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
	<Stf as ParentchainPalletInstancesInterface<StateHandler::StateT, ParentchainHeader>>::Error:
		Debug,
	NodeMetadataRepository: AccessNodeMetadata,
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256> + QueryShardState,
	StateHandler::StateT: Encode + SgxExternalitiesTrait,
	Stf: ParentchainPalletInstancesInterface<StateHandler::StateT, ParentchainHeader>
		+ UpdateState<
			StateHandler::StateT,
			<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType,
		>,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync,
{
	fn initialize_new_shards(
		&self,
		header: &ParentchainHeader,
		state_diff_update: &BTreeMap<Vec<u8>, Option<Vec<u8>>>,
		shards: &Vec<u8>,
	) -> Result<()> {
		let shards: Vec<ShardIdentifier> = Decode::decode(&mut shards.as_slice())?;

		for shard_id in shards {
			let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard_id)?;
			trace!("Successfully loaded state, updating states ...");

			// per shard (cid) requests
			let per_shard_hashes = storage_hashes_to_update_per_shard(&shard_id);
			let per_shard_update = self
				.ocall_api
				.get_multiple_storages_verified(
					per_shard_hashes,
					header,
					&ParentchainId::Integritee,
				)
				.map(into_map)?;

			Stf::apply_state_diff(&mut state, per_shard_update.into());
			Stf::apply_state_diff(&mut state, state_diff_update.clone().into());
			if let Err(e) = Stf::update_parentchain_integritee_block(&mut state, header.clone()) {
				error!("Could not update parentchain block. {:?}: {:?}", shard_id, e)
			}

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
		> + StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		IntoIterator<Item = (Vec<u8>, Option<Vec<u8>>)>,
	<StateHandler::StateT as SgxExternalitiesTrait>::SgxExternalitiesDiffType:
		From<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
	<Stf as StateCallInterface<TCS, StateHandler::StateT, NodeMetadataRepository>>::Error: Debug,
	TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	G: PartialEq + Encode + Decode + Debug + Clone + Send + Sync,
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
		PH: HeaderTrait<Hash = H256>,
		F: FnOnce(Self::Externalities) -> Self::Externalities,
	{
		let started_at = duration_now();
		let ends_at = started_at + max_exec_duration;

		let (state, state_hash_before_execution) = self.state_handler.load_cloned(shard)?;

		// Execute any pre-processing steps.
		let mut state = prepare_state_function(state);
		let mut executed_and_failed_calls = Vec::<ExecutedOperation<TCS, G>>::new();

		Stf::on_initialize(&mut state, now_as_millis()).unwrap_or_else(|e| {
			error!("on_initialize failed: {:?}", e);
		});

		// Iterate through all calls until time is over.
		for trusted_call_signed in trusted_calls.into_iter() {
			// Break if allowed time window is over.
			if ends_at < duration_now() {
				info!("Aborting execution of trusted calls because slot time is up");
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

		Stf::on_finalize(&mut state).unwrap_or_else(|e| {
			error!("on_finalize failed: {:?}", e);
		});

		let propsing_duration = duration_now() - started_at;
		self.ocall_api
			.update_metrics(vec![EnclaveMetric::StfStateUpodateExecutionDuration(
				propsing_duration,
			)])
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

pub fn shards_key_hash() -> Vec<u8> {
	// here you have to point to a storage value containing a Vec of
	// ShardIdentifiers the enclave uses this to autosubscribe to no shards
	vec![]
}
