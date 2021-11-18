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

use crate::{error::Result, TopPoolOperationHandler};
use ita_stf::TrustedCallSigned;
use itp_stf_executor::{
	traits::{StfExecuteTimedCallsBatch, StfExecuteTimedGettersBatch},
	BatchExecutionResult, ExecutedOperation,
};
use itp_time_utils::now_as_u64;
use itp_types::{ShardIdentifier, H256};
use its_primitives::traits::{Block as SidechainBlockT, SignedBlock as SignedBlockT};
use its_state::{SidechainDB, SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_rpc_author::traits::{AuthorApi, OnBlockCreated, SendState};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{traits::Block as BlockT, MultiSignature};
use std::{time::Duration, vec, vec::Vec};

/// Interface to the trusted calls within the top pool
pub trait TopPoolCallOperator {
	type ParentchainBlockT: BlockT;

	/// Loads trusted calls from the top pool for a given shard
	/// and executes them until either all calls are executed or `max_exec_duration` is reached.
	fn execute_trusted_calls(
		&self,
		latest_onchain_header: &<Self::ParentchainBlockT as BlockT>::Header,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<BatchExecutionResult>;

	/// Retrieves trusted calls from the top pool.
	fn get_trusted_calls(&self, shard: &ShardIdentifier) -> Result<Vec<TrustedCallSigned>>;

	/// Removes the given trusted calls from the top pool.
	/// Returns all hashes that were NOT successfully removed.
	/// FIXME: Hash type should be taken from TrustedCall itself: #515
	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifier,
		calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation>;
}

impl<PB, SB, RpcAuthor, StfExecutor> TopPoolCallOperator
	for TopPoolOperationHandler<PB, SB, RpcAuthor, StfExecutor>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	RpcAuthor:
		AuthorApi<H256, PB::Hash> + OnBlockCreated<Hash = PB::Hash> + SendState<Hash = PB::Hash>,
	StfExecutor: StfExecuteTimedCallsBatch + StfExecuteTimedGettersBatch,
	<StfExecutor as StfExecuteTimedCallsBatch>::Externalities:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
{
	type ParentchainBlockT = PB;

	fn execute_trusted_calls(
		&self,
		latest_onchain_header: &PB::Header,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<BatchExecutionResult> {
		let trusted_calls = &self.get_trusted_calls(shard)?;
		// TODO: remove when we have proper on-boarding of new workers #273.
		if trusted_calls.is_empty() {
			info!("No trusted calls in top for shard: {:?}", shard);
		// We return here when we actually import sidechain blocks because we currently have no
		// means of worker on-boarding. Without on-boarding we have can't get a working multi
		// worker-setup.
		//
		// But if we use this trick (only produce a sidechain block if there are trusted_calls), we
		// we can simply wait with the submission of trusted calls until all workers are ready. Then
		// we don't need to exchange any state and can have a functional multi-worker setup.
		// return Ok(Default::default())
		} else {
			debug!("Got following trusted calls from pool: {:?}", trusted_calls);
		}

		let batch_execution_result = self.stf_executor.execute_timed_calls_batch::<PB, _>(
			trusted_calls,
			latest_onchain_header,
			shard,
			max_exec_duration,
			|s| {
				let mut sidechain_db = SidechainDB::<
					SB::Block,
					<StfExecutor as StfExecuteTimedCallsBatch>::Externalities,
				>::new(s);
				sidechain_db
					.set_block_number(&sidechain_db.get_block_number().map_or(1, |n| n + 1));
				sidechain_db.set_timestamp(&now_as_u64());
				sidechain_db.ext
			},
		)?;

		// FIXME: What to do with failed to remove? Issue #516
		// Failing can only happen in case of decoding / hashing error of trusted operation.
		let _failed_to_remove =
			self.remove_calls_from_pool(shard, batch_execution_result.executed_operations.clone());

		Ok(batch_execution_result)
	}

	fn get_trusted_calls(&self, shard: &ShardIdentifier) -> Result<Vec<TrustedCallSigned>> {
		Ok(self.rpc_author.get_pending_tops_separated(*shard)?.0)
	}

	fn remove_calls_from_pool(
		&self,
		shard: &ShardIdentifier,
		executed_calls: Vec<ExecutedOperation>,
	) -> Vec<ExecutedOperation> {
		let mut failed_to_remove = Vec::new();
		for executed_call in executed_calls {
			if let Err(e) = self.rpc_author.remove_top(
				vec![executed_call.trusted_operation_or_hash.clone()],
				*shard,
				executed_call.is_success(),
			) {
				// We don't want to return here before all calls have been iterated through,
				// hence only throwing an error log and push to `failed_to_remove` vec.
				error!("Error removing trusted call from top pool: Error: {:?}", e);
				failed_to_remove.push(executed_call);
			}
		}
		failed_to_remove
	}
}
