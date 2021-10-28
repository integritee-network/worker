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

use crate::error::Result;
use ita_stf::{AccountId, ShardIdentifier, TrustedCallSigned};
use itp_types::{Amount, OpaqueCall, H256};
use sp_runtime::traits::Block as BlockT;
use std::vec::Vec;

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
		calls: &mut Vec<OpaqueCall>,
	) -> Result<H256>;
}

/// Execute a trusted call on the STF
pub trait StfExecuteTrustedCall {
	fn execute_trusted_call<PB>(
		&self,
		calls: &mut Vec<OpaqueCall>,
		stf_call_signed: &TrustedCallSigned,
		header: &PB::Header,
		shard: ShardIdentifier,
		post_processing: StatePostProcessing,
	) -> Result<Option<(H256, H256)>>
	where
		PB: BlockT<Hash = H256>;
}

/// Execute a batch of trusted calls within a given time window
///
/// If the time expires, any remaining trusted calls will be ignored
/// All executed call hashes are returned.
pub trait StfExecuteTimedCallsBatch {
	fn execute_timed_calls_batch(
		&self,
		callback_calls: &mut Vec<OpaqueCall>,
		trusted_calls: &Vec<TrustedCallSigned>,
		header: &PB::Header,
		shard: ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<Vec<Option<(H256, H256)>>>;
}

///
pub trait StfUpdateState {
	fn update_states<PB>(&self, header: &PB::Header) -> Result<()>
	where
		PB: BlockT<Hash = H256>;
}
