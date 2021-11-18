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
	TopPoolOperationHandler,
};
use codec::Encode;
use ita_stf::{hash::TrustedOperationOrHash, TrustedGetterSigned};
use itp_stf_executor::traits::{StfExecuteTimedCallsBatch, StfExecuteTimedGettersBatch};
use itp_types::{ShardIdentifier, H256};
use its_primitives::traits::{Block as SidechainBlockT, SignedBlock as SignedBlockT};
use its_state::{SidechainState, SidechainSystemExt, StateHash};
use its_top_pool_rpc_author::traits::{AuthorApi, OnBlockCreated, SendState};
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{traits::Block as BlockT, MultiSignature};
use std::{time::Duration, vec, vec::Vec};

/// Interface to the trusted getters within the top pool
pub trait TopPoolGetterOperator {
	/// Loads trusted getters from the top pool for a given shard
	/// and executes them until either all calls are executed or `max_exec_duration` is reached.
	fn execute_trusted_getters_on_shard(
		&self,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<()>;

	/// Retrieves trusted getters from the top pool.
	fn get_trusted_getters(&self, shard: &ShardIdentifier) -> Result<Vec<TrustedGetterSigned>>;

	/// Removes the given trusted getter from the top pool.
	/// FIXME: Hash type should be taken from TrustedGetter itself: #515
	fn remove_getter_from_pool(
		&self,
		shard: &ShardIdentifier,
		getter: TrustedOperationOrHash<H256>,
	) -> Result<Vec<H256>>;
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
	fn execute_trusted_getters_on_shard(
		&self,
		shard: &ShardIdentifier,
		max_exec_duration: Duration,
	) -> Result<()> {
		type StfExecutorResult<T> = itp_stf_executor::error::Result<T>;

		self.stf_executor
			.execute_timed_getters_batch(
				&self.get_trusted_getters(shard)?,
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

					// Directly remove executed/skipped getter from pool.
					if let Err(e) = self.remove_getter_from_pool(
						shard,
						TrustedOperationOrHash::Hash(hash_of_getter),
					) {
						error!("Error removing trusted getter from top pool: Error: {:?}", e);
					}
				},
			)
			.map_err(Error::StfExecution)
	}

	fn get_trusted_getters(&self, shard: &ShardIdentifier) -> Result<Vec<TrustedGetterSigned>> {
		Ok(self.rpc_author.get_pending_tops_separated(*shard)?.1)
	}

	fn remove_getter_from_pool(
		&self,
		shard: &ShardIdentifier,
		getter: TrustedOperationOrHash<H256>,
	) -> Result<Vec<H256>> {
		Ok(self.rpc_author.remove_top(vec![getter], *shard, false)?)
	}
}
