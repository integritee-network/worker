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
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{AccountId, ShardIdentifier, TrustedOperation},
};
use itp_types::H256;
use sp_runtime::traits::Header as HeaderTrait;
use std::time::Duration;

/// Post-processing steps after executing STF
pub enum StatePostProcessing {
	None,
	Prune,
}

/// Allows signing of a trusted call with the enclave account that is registered in the STF.
///
/// The signing key is derived from the shielding key, which guarantees that all enclaves sign the same key.
pub trait StfEnclaveSigning<TCS>
where
	TCS: PartialEq + Encode + Debug,
{
	fn get_enclave_account(&self) -> Result<AccountId>;

	fn sign_call_with_self<TC: Encode + Debug + TrustedCallSigning<TCS>>(
		&self,
		trusted_call: &TC,
		shard: &ShardIdentifier,
	) -> Result<TCS>;
}

/// Proposes a state update to `Externalities`.
pub trait StateUpdateProposer<TCS, G>
where
	TCS: PartialEq + Encode + Decode + Debug + Send + Sync,
	G: PartialEq + Encode + Decode + Debug + Send + Sync,
{
	type Externalities: SgxExternalitiesTrait + Encode;

	/// Executes trusted calls within a given time frame without permanent state mutation.
	///
	/// All executed call hashes and the mutated state are returned.
	/// If the time expires, any remaining trusted calls within the batch will be ignored.
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
		F: FnOnce(Self::Externalities) -> Self::Externalities;
}

/// Updates the STF state for a specific header.
///
/// Cannot be implemented for a generic header currently, because the runtime expects a ParentchainHeader.
pub trait StfUpdateState<PCH, PCID> {
	fn update_states(&self, header: &PCH, parentchain_id: &PCID) -> Result<()>;
}
