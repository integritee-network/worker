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
		StatePostProcessing, StateUpdateProposer, StfExecuteGenericUpdate, StfExecuteShieldFunds,
		StfExecuteTimedGettersBatch, StfExecuteTrustedCall, StfUpdateState,
	},
	BatchExecutionResult, ExecutedOperation, ExecutionStatus,
};
use codec::{Decode, Encode};
use ita_stf::{
	hash::TrustedOperationOrHash,
	stf_sgx::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, ParentchainHeader, ShardIdentifier, StateTypeDiff, Stf, TrustedCall,
	TrustedCallSigned, TrustedGetterSigned,
};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_stf_state_handler::{handle_state::HandleState, query_shard_state::QueryShardState};
use itp_storage::StorageEntryVerified;
use itp_storage_verifier::GetStorageVerified;
use itp_types::{Amount, OpaqueCall, H256};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{
	app_crypto::sp_core::blake2_256,
	traits::{Block as BlockT, Header as HeaderTrait},
};
use std::{
	collections::BTreeMap,
	fmt::Debug,
	format,
	marker::PhantomData,
	result::Result as StdResult,
	sync::Arc,
	time::{Duration, SystemTime},
	vec::Vec,
};

pub struct StfExecutor<OCallApi, StateHandler, ExternalitiesT> {
	ocall_api: Arc<OCallApi>,
	state_handler: Arc<StateHandler>,
	_phantom_externalities: PhantomData<ExternalitiesT>,
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
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
	fn execute_trusted_call_on_stf<PH, E>(
		&self,
		state: &mut E,
		stf_call_signed: &TrustedCallSigned,
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

		let operation = stf_call_signed.clone().into_trusted_operation(true);
		let operation_hash: H256 = blake2_256(&operation.encode()).into();
		debug!("Operation hash {:?}", operation_hash);

		if let StatePostProcessing::Prune = post_processing {
			state.prune_state_diff();
		}

		Ok(ExecutedOperation::success(operation_hash, top_or_hash, extrinsic_call_backs))
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteTrustedCall
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
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

		let executed_call = self.execute_trusted_call_on_stf(
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
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	fn execute_shield_funds(
		&self,
		account: AccountId,
		amount: Amount,
		shard: &ShardIdentifier,
	) -> Result<H256> {
		let (state_lock, mut state) = self.state_handler.load_for_mutation(shard)?;

		let root = Stf::get_root(&mut state);
		let nonce = Stf::account_nonce(&mut state, &root);

		let trusted_call = TrustedCallSigned::new(
			TrustedCall::balance_shield(root, account, amount),
			nonce,
			Default::default(), //don't care about signature here
		);

		Stf::execute(&mut state, trusted_call, &mut Vec::<OpaqueCall>::new())
			.map_err::<Error, _>(|e| e.into())?;

		self.state_handler.write(state, state_lock, shard).map_err(|e| e.into())
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfUpdateState
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT> + QueryShardState,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	fn update_states<PB>(&self, header: &PB::Header) -> Result<()>
	where
		PB: BlockT<Hash = H256, Header = ParentchainHeader>,
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

		// Update parentchain block on all states.
		let shards = self.state_handler.list_shards()?;
		for shard_id in shards {
			let (state_lock, mut state) = self.state_handler.load_for_mutation(&shard_id)?;
			match Stf::update_parentchain_block(&mut state, header.clone()) {
				Ok(_) => {
					self.state_handler.write(state, state_lock, &shard_id)?;
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

						self.state_handler.write(state, state_lock, &shard_id)?;
					}
				},
				None => debug!("No shards are on the chain yet"),
			};
		};
		Ok(())
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StateUpdateProposer
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
	StateHandler: HandleState<StateT = ExternalitiesT>,
	ExternalitiesT: SgxExternalitiesTrait + Encode,
{
	type Externalities = ExternalitiesT;

	fn propose_state_update<PH, F>(
		&self,
		trusted_calls: &[TrustedCallSigned],
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

		let state = self.state_handler.load_initialized(shard)?;

		let state_hash_before_execution: H256 = state.using_encoded(blake2_256).into();

		// Execute any pre-processing steps.
		let mut state = prepare_state_function(state);
		let mut executed_calls = Vec::<ExecutedOperation>::new();

		// Iterate through all calls until time is over.
		for trusted_call_signed in trusted_calls.into_iter() {
			match self.execute_trusted_call_on_stf(
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

			// Break if allowed time window is over.
			if ends_at < duration_now() {
				break
			}
		}

		Ok(BatchExecutionResult {
			executed_operations: executed_calls,
			state_hash_before_execution,
			state_after_execution: state,
		})
	}
}

impl<OCallApi, StateHandler, ExternalitiesT> StfExecuteTimedGettersBatch
	for StfExecutor<OCallApi, StateHandler, ExternalitiesT>
where
	OCallApi: EnclaveAttestationOCallApi + GetStorageVerified,
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
) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
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

#[cfg(all(feature = "test", feature = "sgx"))]
pub mod tests {
	use super::*;
	use ita_stf::{
		test_genesis::{test_account, test_genesis_setup, TEST_ACC_FUNDS},
		Balance, State, TrustedGetter,
	};
	use itp_test::{
		builders::parentchain_header_builder::ParentchainHeaderBuilder,
		mock::{handle_state_mock::HandleStateMock, onchain_mock::OnchainMock},
	};
	use itp_types::Header;
	use sgx_tstd::panic;
	use sp_core::Pair;
	use std::vec;

	// 	pub fn propose_state_update() {
	// 		// given
	// 		let onchain_mock = OnchainMock::default();
	// 		let mrenclave = onchain_mock.get_mrenclave_of_self().unwrap().m;
	// 		let shard = ShardIdentifier::default();
	// 		let sender = test_account();
	// 		let signed_call = TrustedCall::balance_set_balance(
	// 			sender.public().into(),
	// 			sender.public().into(),
	// 			42,
	// 			42,
	// 		)
	// 		.sign(&sender.into(), 0, &mrenclave, &shard);
	// 		let shard = ShardIdentifier::default();
	// 		let stf_executor = stf_executor();
	// 		let execution_duration = Duration::from_secs(10000);
	//
	// 		// when
	// 		stf_executor
	// 			.propose_state_update(
	// 				&vec![signed_call.clone()],
	// 				&ParentchainHeaderBuilder::default().build(),
	// 				&shard,
	// 				execution_duration,
	// 				|state| {
	// 					// then
	// 					//assert_eq!(*trusted_getter_signed, trusted_getter);
	// 					state
	// 				},
	// 			)
	// 			.unwrap();
	// 	}

	pub fn execute_timed_getters_batch_executes_if_enough_time() {
		// given
		let sender = test_account();
		let trusted_getter =
			TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
		let shard = ShardIdentifier::default();
		let stf_executor = stf_executor();
		let execution_duration = Duration::from_secs(10000);

		// when
		assert!(panic::catch_unwind(|| {
			stf_executor.execute_timed_getters_batch(
				&vec![trusted_getter.clone()],
				&shard,
				execution_duration,
				|trusted_getter_signed: &TrustedGetterSigned,
				 _state_result: Result<Option<Vec<u8>>>| {
					// then
					assert_eq!(*trusted_getter_signed, trusted_getter);
					panic!("test should enter here");
				},
			)
		})
		.is_err());
	}

	pub fn execute_timed_getters_does_not_execute_more_than_once_if_not_enough_time() {
		// given
		let sender = test_account();
		let trusted_getter =
			TrustedGetter::free_balance(sender.public().into()).sign(&sender.clone().into());
		let trusted_getter_two =
			TrustedGetter::reserved_balance(sender.public().into()).sign(&sender.into());
		let shard = ShardIdentifier::default();
		let stf_executor = stf_executor();
		let execution_duration = Duration::ZERO;

		// when
		stf_executor
			.execute_timed_getters_batch(
				&vec![trusted_getter.clone(), trusted_getter_two],
				&shard,
				execution_duration,
				|trusted_getter_signed: &TrustedGetterSigned,
				 _state_result: Result<Option<Vec<u8>>>| {
					// then (second getter should not be executed)
					assert_eq!(*trusted_getter_signed, trusted_getter);
				},
			)
			.unwrap();
	}

	pub fn execute_timed_getters_batch_returns_early_when_no_getter() {
		// given
		let shard = ShardIdentifier::default();
		let stf_executor = stf_executor();
		let execution_duration = Duration::from_secs(10000);

		// when
		stf_executor
			.execute_timed_getters_batch(
				&vec![],
				&shard,
				execution_duration,
				|_trusted_getter_signed: &TrustedGetterSigned,
				 _state_result: Result<Option<Vec<u8>>>| {
					// then
					panic!("Test should not enter here");
				},
			)
			.unwrap();
	}

	pub fn execute_update_works() {
		// given
		let shard = ShardIdentifier::default();
		let stf_executor = stf_executor();
		let key = "my_key".encode();
		let value = "my_value".encode();
		let old_state_hash =
			state_hash(stf_executor.state_handler.load_initialized(&shard).unwrap());

		// when
		let (result, updated_state_hash) = stf_executor
			.execute_update::<_, _, Error>(&shard, |mut state| {
				state.insert(key.clone(), value.clone());
				Ok((state, 0))
			})
			.unwrap();

		// then
		assert_eq!(result, 0);
		assert_ne!(updated_state_hash, old_state_hash);

		// Ensure that state has been written.
		let updated_state = stf_executor.state_handler.load_initialized(&shard).unwrap();
		let retrieved_vale = updated_state.get(key.as_slice()).unwrap();
		assert_eq!(*retrieved_vale, value);
	}

	pub fn get_stf_state_works() {
		let sender = test_account();
		let signed_getter =
			TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
		let mut state = test_state();

		let encoded_balance = get_stf_state(&signed_getter, &mut state).unwrap().unwrap();

		let balance = Balance::decode(&mut encoded_balance.as_slice()).unwrap();

		assert_eq!(balance, TEST_ACC_FUNDS);
	}

	pub fn upon_false_signature_get_stf_state_errs() {
		let sender = AccountId::default();
		let wrong_signer = test_account();
		let signed_getter = TrustedGetter::free_balance(sender).sign(&wrong_signer.into());
		let mut state = test_state();

		assert!(get_stf_state(&signed_getter, &mut state).is_err());
	}

	// Helper Functions
	fn stf_executor() -> StfExecutor<OnchainMock, HandleStateMock, State> {
		StfExecutor::new(Arc::new(OnchainMock::default()), Arc::new(HandleStateMock::default()))
	}

	fn test_state() -> State {
		let mut state = Stf::init_state();
		test_genesis_setup(&mut state);
		state
	}

	fn state_hash(state: State) -> H256 {
		state.using_encoded(blake2_256).into()
	}
}
