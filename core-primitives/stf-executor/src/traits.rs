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

use crate::{error::Result, BatchExecutionResult};
use codec::Encode;
use ita_stf::{
	AccountId, ParentchainHeader, ShardIdentifier, TrustedGetterSigned, TrustedOperation,
};
use itp_types::{Amount, OpaqueCall, H256};
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::traits::Header as HeaderTrait;
use std::{fmt::Debug, result::Result as StdResult, time::Duration, vec::Vec};

/// Post-processing steps after executing STF
pub enum StatePostProcessing {
	None,
	Prune,
}

/// Execute shield funds on the STF
pub trait StfExecuteShieldFunds {
	fn execute_shield_funds(
		&self,
		account: AccountId,
		amount: Amount,
		shard: &ShardIdentifier,
	) -> Result<H256>;
}

/// Execute a trusted call on the STF
pub trait StfExecuteTrustedCall {
	fn execute_trusted_call<PH>(
		&self,
		calls: &mut Vec<OpaqueCall>,
		stf_call_signed: &TrustedOperation,
		header: &PH,
		shard: &ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<Option<H256>>
	where
		PH: HeaderTrait<Hash = H256>;
}

/// Proposes a state update to `Externalities`.
pub trait StateUpdateProposer {
	type Externalities: SgxExternalitiesTrait + Encode;

	/// Executes trusted calls within a given time frame without permanent state mutation.
	///
	/// All executed call hashes and the mutated state are returned.
	/// If the time expires, any remaining trusted calls within the batch will be ignored.
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
		F: FnOnce(Self::Externalities) -> Self::Externalities;
}

/// Execute a batch of trusted getter within a given time window
///
///
pub trait StfExecuteTimedGettersBatch {
	type Externalities: SgxExternalitiesTrait + Encode;

	fn execute_timed_getters_batch<F>(
		&self,
		trusted_getters: &[TrustedGetterSigned],
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
		getter_callback: F,
	) -> Result<()>
	where
		F: Fn(&TrustedGetterSigned, Result<Option<Vec<u8>>>);
}

/// Execute a generic function on the STF state
pub trait StfExecuteGenericUpdate {
	type Externalities: SgxExternalitiesTrait + Encode;

	fn execute_update<F, ResultT, ErrorT>(
		&self,
		shard: &ShardIdentifier,
		update_function: F,
	) -> Result<(ResultT, H256)>
	where
		F: FnOnce(Self::Externalities) -> StdResult<(Self::Externalities, ResultT), ErrorT>,
		ErrorT: Debug;
}

/// Updates the STF state for a specific header.
///
/// Cannot be implemented for a generic header currently, because the runtime expects a ParentchainHeader.
pub trait StfUpdateState {
	fn update_states(&self, header: &ParentchainHeader) -> Result<()>;
}
