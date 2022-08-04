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
	traits::{
		StatePostProcessing, StateUpdateProposer, StfExecuteGenericUpdate,
		StfExecuteTimedGettersBatch, StfUpdateState,
	},
	BatchExecutionResult, ExecutedOperation,
};
use codec::{Decode, Encode};
use ita_stf::{
	hash::{Hash, TrustedOperationOrHash},
	stf_sgx::{shards_key_hash, storage_hashes_to_update_per_shard},
	ParentchainHeader, ShardIdentifier, StateTypeDiff, Stf, TrustedGetterSigned, TrustedOperation,
};
use itp_node_api::metadata::{pallet_teerex::TeerexCallIndexes, provider::AccessNodeMetadata};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_time_utils::duration_now;
use itp_types::{storage::StorageEntryVerified, OpaqueCall, H256};
use log::*;
use sp_runtime::{app_crypto::sp_core::blake2_256, traits::Header as HeaderTrait};
use std::{
	collections::BTreeMap, fmt::Debug, format, result::Result as StdResult, sync::Arc,
	time::Duration, vec::Vec,
};

pub struct StfExecutor<OCallApi, StateHandler, NodeMetadataRepository> {
	ocall_api: Arc<OCallApi>,
	state_handler: Arc<StateHandler>,
	node_metadata_repo: Arc<NodeMetadataRepository>,
}

impl<OCallApi, StateHandler, NodeMetadataRepository>
	StfExecutor<OCallApi, StateHandler, NodeMetadataRepository>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: TeerexCallIndexes,
{
	pub fn new(
		ocall_api: Arc<OCallApi>,
		state_handler: Arc<StateHandler>,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Self {
		StfExecutor { ocall_api, state_handler, node_metadata_repo }
	}

	/// Execute a trusted call on the STF
	///
	/// We distinguish between an error in the execution, which maps to `Err` and
	/// an invalid trusted call, which results in `Ok(ExecutionStatus::Failure)`. The latter
	/// can be used to remove the trusted call from a queue. In the former case we might keep the
	/// trusted call and just re-try the operation.
	fn execute_trusted_call_on_stf<PH, E>(
		&self,
		state: &mut E,
		trusted_operation: &TrustedOperation,
		header: &PH,
		shard: &ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<ExecutedOperation>
	where
		PH: HeaderTrait<Hash = H256>,
		E: SgxExternalitiesTrait,
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

		let unshield_funds_fn = self
			.node_metadata_repo
			.get_from_metadata(|m| m.unshield_funds_call_indexes())??;

		// Necessary because light client sync may not be up to date
		// see issue #208
		debug!("Update STF storage!");
		let storage_hashes = Stf::get_storage_hashes_to_update(&trusted_call);
		let update_map = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header)
			.map(into_map)?;

		Stf::update_storage(state, &update_map.into());

		debug!("execute STF, call with nonce {}", trusted_call.nonce);
		let mut extrinsic_call_backs: Vec<OpaqueCall> = Vec::new();
		if let Err(e) =
			Stf::execute(state, trusted_call.clone(), &mut extrinsic_call_backs, unshield_funds_fn)
		{
			error!("Stf::execute failed: {:?}", e);
			return Ok(ExecutedOperation::failed(top_or_hash))
		}

		let operation_hash = trusted_operation.hash();
		debug!("Operation hash {:?}", operation_hash);

		if let StatePostProcessing::Prune = post_processing {
			state.prune_state_diff();
		}

		Ok(ExecutedOperation::success(operation_hash, top_or_hash, extrinsic_call_backs))
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository> StfUpdateState
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256> + QueryShardState,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
{
	fn update_states(&self, header: &ParentchainHeader) -> Result<()> {
		debug!("Update STF storage upon block import!");
		let storage_hashes = Stf::storage_hashes_to_update_on_block();

		if storage_hashes.is_empty() {
			return Ok(())
		}

		// global requests they are the same for every shard
		let state_diff_update: StateTypeDiff = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header)
			.map(into_map)?
			.into();

		// Update parentchain block on all states.
		let shards = self.state_handler.list_shards()?;
		for shard_id in shards {
			let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard_id)?;
			match Stf::update_parentchain_block(&mut state, header.clone()) {
				Ok(_) => {
					self.state_handler.write_after_mutation(state, state_lock, &shard_id)?;
				},
				Err(e) => error!("Could not update parentchain block. {:?}: {:?}", shard_id, e),
			}
		}

		// look for new shards an initialize them
		if let Some(maybe_shards) = state_diff_update.get(&shards_key_hash()) {
			match maybe_shards {
				Some(shards) => {
					let shards: Vec<ShardIdentifier> = Decode::decode(&mut shards.as_slice())?;

					for shard_id in shards {
						let (state_lock, mut state) =
							self.state_handler.load_for_mutation(&shard_id)?;
						trace!("Successfully loaded state, updating states ...");

						// per shard (cid) requests
						let per_shard_hashes = storage_hashes_to_update_per_shard(&shard_id);
						let per_shard_update = self
							.ocall_api
							.get_multiple_storages_verified(per_shard_hashes, header)
							.map(into_map)?;

						Stf::update_storage(&mut state, &per_shard_update.into());
						Stf::update_storage(&mut state, &state_diff_update);
						if let Err(e) = Stf::update_parentchain_block(&mut state, header.clone()) {
							error!("Could not update parentchain block. {:?}: {:?}", shard_id, e)
						}

						self.state_handler.write_after_mutation(state, state_lock, &shard_id)?;
					}
				},
				None => debug!("No shards are on the chain yet"),
			};
		};
		Ok(())
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository> StateUpdateProposer
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: TeerexCallIndexes,
{
	type Externalities = StateHandler::StateT;

	fn propose_state_update<PH, F>(
		&self,
		trusted_calls: &[TrustedOperation],
		header: &PH,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
		prepare_state_function: F,
	) -> Result<BatchExecutionResult<Self::Externalities>>
	where
		PH: HeaderTrait<Hash = H256>,
		F: FnOnce(Self::Externalities) -> Self::Externalities,
	{
		let ends_at = duration_now() + max_exec_duration;

		let state = self.state_handler.load(shard)?;
		let state_hash_before_execution = state_hash(&state);

		// Execute any pre-processing steps.
		let mut state = prepare_state_function(state);
		let mut executed_and_failed_calls = Vec::<ExecutedOperation>::new();

		// Iterate through all calls until time is over.
		for trusted_call_signed in trusted_calls.into_iter() {
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
					error!("Fatal Error. Failed to attempt call execution: {:?}", e);
				},
			};

			// Break if allowed time window is over.
			if ends_at < duration_now() {
				break
			}
		}

		Ok(BatchExecutionResult {
			executed_operations: executed_and_failed_calls,
			state_hash_before_execution,
			state_after_execution: state,
		})
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository> StfExecuteTimedGettersBatch
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi,
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
{
	type Externalities = StateHandler::StateT;

	fn execute_timed_getters_batch<F>(
		&self,
		trusted_getters: &[TrustedGetterSigned],
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
		getter_callback: F,
	) -> Result<()>
	where
		F: Fn(&TrustedGetterSigned, Result<Option<Vec<u8>>>),
	{
		let ends_at = duration_now() + max_exec_duration;

		// return early if we have no trusted getters, so we don't decrypt the state unnecessarily
		if trusted_getters.is_empty() {
			return Ok(())
		}

		// load state once per shard
		let mut state = self.state_handler.load(&shard)?;

		for trusted_getter_signed in trusted_getters.into_iter() {
			// get state
			let getter_state = get_stf_state(trusted_getter_signed, &mut state);

			debug!("Executing trusted getter");

			getter_callback(trusted_getter_signed, getter_state);

			// Check time
			if ends_at < duration_now() {
				return Ok(())
			}
		}

		Ok(())
	}
}

impl<OCallApi, StateHandler, NodeMetadataRepository> StfExecuteGenericUpdate
	for StfExecutor<OCallApi, StateHandler, NodeMetadataRepository>
where
	StateHandler: HandleState<HashType = H256>,
	StateHandler::StateT: SgxExternalitiesTrait + Encode,
	NodeMetadataRepository: AccessNodeMetadata,
{
	type Externalities = StateHandler::StateT;

	fn execute_update<F, ResultT, ErrorT>(
		&self,
		shard: &ShardIdentifier,
		update_function: F,
	) -> Result<(ResultT, H256)>
	where
		F: FnOnce(Self::Externalities) -> StdResult<(Self::Externalities, ResultT), ErrorT>,
		ErrorT: Debug,
	{
		let (state_lock, state) = self.state_handler.load_for_mutation(&shard)?;

		let (new_state, result) = update_function(state).map_err(|e| {
			Error::Other(format!("Failed to run update function on STF state: {:?}", e).into())
		})?;

		let new_state_hash = self
			.state_handler
			.write_after_mutation(new_state, state_lock, shard)
			.map_err(|e| Error::StateHandler(e))?;
		Ok((result, new_state_hash))
	}
}

fn into_map(
	storage_entries: Vec<StorageEntryVerified<Vec<u8>>>,
) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
	storage_entries.into_iter().map(|e| e.into_tuple()).collect()
}

/// Compute the state hash.
///
/// TODO: This should be implemented on the State itself. We have multiple implementations,
/// the other one being in the sidechain.
pub(crate) fn state_hash<ExternalitiesT: SgxExternalitiesTrait + Encode>(
	state: &ExternalitiesT,
) -> H256 {
	state.state().using_encoded(blake2_256).into()
}

/// Execute a trusted getter on a state and return its value, if available.
///
/// Also verifies the signature of the trusted getter and returns an error
/// if it's invalid.
pub(crate) fn get_stf_state<E: SgxExternalitiesTrait>(
	trusted_getter_signed: &TrustedGetterSigned,
	state: &mut E,
) -> Result<Option<Vec<u8>>> {
	debug!("verifying signature of TrustedGetterSigned");
	if let false = trusted_getter_signed.verify_signature() {
		return Err(Error::OperationHasInvalidSignature)
	}

	debug!("calling into STF to get state");
	Ok(Stf::get_state(state, trusted_getter_signed.clone().into()))
}
