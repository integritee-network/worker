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

// #[cfg(all(not(feature = "std"), feature = "sgx"))]
// use crate::sgx_reexport_prelude::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::untrusted::time::SystemTimeEx;

use crate::{
	error::{Error, Result},
	traits::{
		StatePostProcessing, StfExecuteGenericUpdate, StfExecuteShieldFunds,
		StfExecuteTimedCallsBatch, StfExecuteTimedGettersBatch, StfExecuteTrustedCall,
		StfUpdateState,
	},
	BatchExecutionResult, ExecutedOperation, ExecutionStatus,
};
use codec::{Decode, Encode};
use ita_stf::{
	hash::TrustedOperationOrHash,
	stf_sgx::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, ShardIdentifier, StateTypeDiff, Stf, TrustedCall, TrustedCallSigned,
	TrustedGetterSigned,
};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_stf_state_handler::handle_state::HandleState;
use itp_storage::StorageEntryVerified;
use itp_storage_verifier::GetStorageVerified;
use itp_types::{Amount, OpaqueCall, H256};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{
	app_crypto::sp_core::blake2_256,
	traits::{Block as BlockT, Header, UniqueSaturatedInto},
};
use std::{
	collections::HashMap,
	fmt::Debug,
	format,
	marker::PhantomData,
	result::Result as StdResult,
	sync::Arc,
	time::{Duration, SystemTime},
	vec::Vec,
};

/// STF Executor implementation
///
///
pub struct StfExecutor<OCallApi, StateHandler, ExternalitiesT> {
	ocall_api: Arc<OCallApi>,
	state_handler: Arc<StateHandler>,
	_phantom_externalities: PhantomData<ExternalitiesT>,
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	pub fn new(ocall_api: Arc<OCallApi>, state_handler: Arc<StateHandler>) -> Self {
		StfExecutor { ocall_api, state_handler, _phantom_externalities: Default::default() }
	}

	/// Execute a trusted call on the STF
	///
	/// We distinguish between an error in the execution, which maps to `Err` and
	/// an invalid trusted call, which results in `Ok(ExecutionStatus::Failure)`. The latter
	/// can be used to remove the trusted call from a queue. In the former case we might keep the
	/// trusted call and just re-try the operation.
	fn execute_trusted_call_on_stf<PB, E>(
		&self,
		state: &mut E,
		stf_call_signed: &TrustedCallSigned,
		header: &PB::Header,
		shard: &ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<ExecutedOperation>
	where
		PB: BlockT<Hash = H256>,
		E: SgxExternalitiesTrait,
	{
		debug!("query mrenclave of self");
		let mrenclave = self.ocall_api.get_mrenclave_of_self()?;
		//debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());

		let top_or_hash = top_or_hash::<H256>(stf_call_signed.clone(), true);

		if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
			error!("TrustedCallSigned: bad signature");
			// do not panic here or users will be able to shoot workers dead by supplying a bad signature
			return Ok(ExecutedOperation::failed(top_or_hash))
		}

		// Necessary because light client sync may not be up to date
		// see issue #208
		debug!("Update STF storage!");
		let storage_hashes = Stf::get_storage_hashes_to_update(&stf_call_signed);
		let update_map = self
			.ocall_api
			.get_multiple_storages_verified(storage_hashes, header)
			.map(into_map)?;

		Stf::update_storage(state, &update_map.into());

		debug!("execute STF");
		let mut extrinsic_call_backs: Vec<OpaqueCall> = Vec::new();
		if let Err(e) = Stf::execute(state, stf_call_signed.clone(), &mut extrinsic_call_backs) {
			error!("Stf::execute failed: {:?}", e);
			return Ok(ExecutedOperation::failed(top_or_hash))
		}

		let call_hash: H256 = blake2_256(&stf_call_signed.encode()).into();
		debug!("Call hash {:?}", call_hash);

		if let StatePostProcessing::Prune = post_processing {
			state.prune_state_diff();
		}

		Ok(ExecutedOperation::success(call_hash, top_or_hash, extrinsic_call_backs))
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteTrustedCall
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	fn execute_trusted_call<PB>(
		&self,
		calls: &mut Vec<OpaqueCall>,
		stf_call_signed: &TrustedCallSigned,
		header: &PB::Header,
		shard: &ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<Option<H256>>
	where
		PB: BlockT<Hash = H256>,
	{
		// load state before executing any calls
		let (state_lock, mut state) = self.state_handler.load_for_mutation(shard)?;

		let executed_call = self.execute_trusted_call_on_stf::<PB, _>(
			&mut state,
			stf_call_signed,
			header,
			shard,
			post_processing,
		)?;

		let (maybe_call_hash, mut extrinsic_callbacks) = match executed_call.status {
			ExecutionStatus::Success(call_hash, e) => (Some(call_hash), e),
			ExecutionStatus::Failure => (None, Vec::new()),
		};

		calls.append(&mut extrinsic_callbacks);

		trace!("Updating state of shard {:?}", shard);
		self.state_handler.write(state, state_lock, shard)?;

		Ok(maybe_call_hash)
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteShieldFunds
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	fn execute_shield_funds(
		&self,
		account: AccountId,
		amount: Amount,
		shard: &ShardIdentifier,
		calls: &mut Vec<OpaqueCall>,
	) -> Result<H256> {
		let (state_lock, mut state) = self.state_handler.load_for_mutation(shard)?;

		let root = Stf::get_root(&mut state);
		let nonce = Stf::account_nonce(&mut state, &root);

		let trusted_call = TrustedCallSigned::new(
			TrustedCall::balance_shield(root, account, amount),
			nonce,
			Default::default(), //don't care about signature here
		);

		Stf::execute(&mut state, trusted_call, calls).map_err::<Error, _>(|e| e.into())?;

		self.state_handler.write(state, state_lock, shard).map_err(|e| e.into())
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfUpdateState
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	fn update_states<PB>(&self, header: &PB::Header) -> Result<()>
	where
		PB: BlockT<Hash = H256>,
	{
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

						// block number is purged from the substrate state so it can't be read like other storage values
						// The number conversion is a bit unfortunate, but I wanted to prevent making the stf generic for now
						Stf::update_layer_one_block_number(
							&mut state,
							(*header.number()).unique_saturated_into(),
						);

						self.state_handler.write(state, state_lock, &shard_id)?;
					}
				},
				None => debug!("No shards are on the chain yet"),
			};
		};
		Ok(())
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteTimedCallsBatch
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	type Externalities = ExternalitiesT;

	fn execute_timed_calls_batch<PB, F>(
		&self,
		trusted_calls: &[TrustedCallSigned],
		header: &PB::Header,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
		prepare_state_function: F,
	) -> Result<BatchExecutionResult>
	where
		PB: BlockT<Hash = H256>,
		F: FnOnce(Self::Externalities) -> Self::Externalities,
	{
		let ends_at = duration_now() + max_exec_duration;

		let (state_lock, state) = self.state_handler.load_for_mutation(shard)?;

		let previous_state_hash: H256 = state.using_encoded(blake2_256).into();

		let mut state = prepare_state_function(state); // execute any pre-processing steps
		let mut executed_calls = Vec::<ExecutedOperation>::new();

		for trusted_call_signed in trusted_calls.into_iter() {
			match self.execute_trusted_call_on_stf::<PB, _>(
				&mut state,
				&trusted_call_signed,
				header,
				shard,
				StatePostProcessing::None,
			) {
				Ok(executed_call) => {
					executed_calls.push(executed_call);
				},
				Err(e) => {
					error!("Error executing trusted call (will not push top hash): {:?}", e);
				},
			};

			// Check time
			if ends_at < duration_now() {
				break
			}
		}

		self.state_handler
			.write(state, state_lock, shard)
			.map_err(|e| Error::StateHandler(e))?;

		Ok(BatchExecutionResult { executed_operations: executed_calls, previous_state_hash })
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteTimedGettersBatch
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	type Externalities = ExternalitiesT;

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
		let mut state = self.state_handler.load_initialized(&shard)?;

		for trusted_getter_signed in trusted_getters.into_iter() {
			// get state
			let getter_state = get_stf_state(trusted_getter_signed, &mut state);

			getter_callback(trusted_getter_signed, getter_state);

			// Check time
			if ends_at < duration_now() {
				return Ok(())
			}
		}

		Ok(())
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteGenericUpdate
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + EnclaveOnChainOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	type Externalities = ExternalitiesT;

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
			.write(new_state, state_lock, shard)
			.map_err(|e| Error::StateHandler(e))?;
		Ok((result, new_state_hash))
	}
}

fn into_map(
	storage_entries: Vec<StorageEntryVerified<Vec<u8>>>,
) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
	storage_entries.into_iter().map(|e| e.into_tuple()).collect()
}

/// Returns current duration since unix epoch.
///
/// TODO: Duplicated from sidechain/consensus/slots. Extract to a crate where it can be shared.
fn duration_now() -> Duration {
	let now = SystemTime::now();
	now.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_else(|e| {
		panic!("Current time {:?} is before unix epoch. Something is wrong: {:?}", now, e)
	})
}

fn top_or_hash<H>(tcs: TrustedCallSigned, direct: bool) -> TrustedOperationOrHash<H> {
	TrustedOperationOrHash::<H>::Operation(tcs.into_trusted_operation(direct))
}

/// Execute a trusted getter on a state and return its value, if available.
///
/// Also verifies the signature of the trusted getter and returns an error
/// if it's invalid.
fn get_stf_state<E: SgxExternalitiesTrait>(
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
