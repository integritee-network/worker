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

use crate::error::{Error, Result};
use codec::Encode;
use ita_stf::{hash::TrustedOperationOrHash, TrustedGetterSigned};
use itp_stf_executor::{
	traits::{StfExecuteTimedCallsBatch, StfExecuteTimedGettersBatch},
	BatchExecutionResult,
};
use itp_time_utils::now_as_u64;
use itp_types::{ShardIdentifier, H256};
use its_primitives::traits::{Block as SidechainBlockT, SignedBlock as SignedBlockT};
use its_state::{SidechainDB, SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_rpc_author::traits::{AuthorApi, OnBlockCreated, SendState};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{traits::Block as BlockT, MultiSignature};
use std::{format, marker::PhantomData, sync::Arc, time::Duration, vec, vec::Vec};

/// Trait to execute trusted calls from the top pool
pub trait TopPoolCallOperator {
	type ParentchainBlockT: BlockT;

	/// Loads trusted calls from the top pool for a given shard
	/// and executes them until either all calls are executed or `max_exec_duration` is reached.
	fn execute_trusted_calls(
		&self,
		latest_onchain_header: &<Self::ParentchainBlockT as BlockT>::Header,
		shard: H256,
		max_exec_duration: Duration,
	) -> Result<BatchExecutionResult>;
}

/// Trait to execute trusted getters from the top pool
pub trait TopPoolGetterOperator {
	/// Loads trusted getters from the top pool for a given shard
	/// and executes them until either all calls are executed or `max_exec_duration` is reached.
	fn execute_trusted_getters_on_shard(
		&self,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<()>;
}

/// Executes operations on the top pool
///
/// Operations can either be Getters or Calls
pub struct TopPoolOperationHandler<PB, SB, RpcAuthor, StfExecutor> {
	rpc_author: Arc<RpcAuthor>,
	stf_executor: Arc<StfExecutor>,
	_phantom: PhantomData<(PB, SB)>,
}

impl<PB, SB, RpcAuthor, StfExecutor> TopPoolOperationHandler<PB, SB, RpcAuthor, StfExecutor>
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
	pub fn new(rpc_author: Arc<RpcAuthor>, stf_executor: Arc<StfExecutor>) -> Self {
		TopPoolOperationHandler { rpc_author, stf_executor, _phantom: Default::default() }
	}
}

impl<PB, SB, RpcAuthor, StfExecutor> TopPoolGetterOperator
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
	/// Execute pending trusted getters for the `shard` until `max_exec_duration` is reached.
	fn execute_trusted_getters_on_shard(
		&self,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<()> {
		// Retrieve trusted getters from top pool.
		let trusted_getters = self.rpc_author.get_pending_tops_separated(*shard)?.1;

		type StfExecutorResult<T> = itp_stf_executor::error::Result<T>;

		self.stf_executor
			.execute_timed_getters_batch(
				&trusted_getters,
				shard,
				max_exec_duration,
				|trusted_getter_signed: &TrustedGetterSigned,
				 state_result: StfExecutorResult<Option<Vec<u8>>>| {
					let hash_of_getter =
						self.rpc_author.hash_of(&trusted_getter_signed.clone().into());

					match state_result {
						Ok(r) => {
							// let client know of current state
							trace!("Updating client");
							match self.rpc_author.send_state(hash_of_getter, r.encode()) {
								Ok(_) => trace!("Successfully updated client"),
								Err(e) => error!("Could not send state to client {:?}", e),
							}
						},
						Err(e) => {
							error!("failed to get stf state, skipping trusted getter ({:?})", e);
						},
					};

					// remove getter from pool
					if let Err(e) = self.rpc_author.remove_top(
						vec![TrustedOperationOrHash::Hash(hash_of_getter)],
						*shard,
						false,
					) {
						error!("Error removing trusted operation from top pool: Error: {:?}", e);
					}
				},
			)
			.map_err(Error::StfExecution)
	}
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
		shard: H256,
		max_exec_duration: Duration,
	) -> Result<BatchExecutionResult> {
		// Retrieve trusted calls from top pool.
		let trusted_calls = self.rpc_author.get_pending_tops_separated(shard)?.0;

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
			&trusted_calls,
			latest_onchain_header,
			&shard,
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

		for executed_operation in batch_execution_result.executed_operations.iter() {
			self.rpc_author
				.remove_top(
					vec![executed_operation.trusted_operation_or_hash.clone()],
					shard,
					executed_operation.is_success(),
				)
				.map_err(|e| Error::Other(format!("{:?}", e).into()))?;
		}

		Ok(batch_execution_result)
	}
}
