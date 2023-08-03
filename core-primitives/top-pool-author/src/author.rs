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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
	client_error::Error as ClientError,
	error::{Error as StateRpcError, Result},
	top_filter::Filter,
	traits::{AuthorApi, OnBlockImported},
};
use codec::{Decode, Encode};
use ita_stf::{hash, Getter, TrustedOperation};
use itp_enclave_metrics::EnclaveMetric;
use itp_ocall_api::EnclaveMetricsOCallApi;
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt};
use itp_stf_primitives::types::AccountId;
use itp_stf_state_handler::query_shard_state::QueryShardState;
use itp_top_pool::{
	error::{Error as PoolError, IntoPoolError},
	primitives::{
		BlockHash, InPoolOperation, PoolFuture, TrustedOperationPool, TrustedOperationSource,
		TxHash,
	},
};
use itp_types::{BlockHash as SidechainBlockHash, ShardIdentifier};
use jsonrpc_core::{
	futures::future::{ready, TryFutureExt},
	Error as RpcError,
};
use log::*;
use sp_runtime::generic;
use std::{boxed::Box, sync::Arc, vec::Vec};

/// Define type of TOP filter that is used in the Author
#[cfg(feature = "sidechain")]
pub type AuthorTopFilter = crate::top_filter::CallsOnlyFilter;
#[cfg(feature = "offchain-worker")]
pub type AuthorTopFilter = crate::top_filter::IndirectCallsOnlyFilter;
#[cfg(feature = "teeracle")] // Teeracle currently does not process any trusted operations
pub type AuthorTopFilter = crate::top_filter::DenyAllFilter;

#[cfg(not(any(feature = "sidechain", feature = "offchain-worker", feature = "teeracle")))]
pub type AuthorTopFilter = crate::top_filter::CallsOnlyFilter;

/// Currently we treat all RPC operations as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such operations, so that the block authors can inject
/// some unique operations via RPC and have them included in the pool.
const TX_SOURCE: TrustedOperationSource = TrustedOperationSource::External;

/// Authoring API for RPC calls
///
///
pub struct Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	TopFilter: Filter<Value = TrustedOperation>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
{
	top_pool: Arc<TopPool>,
	top_filter: TopFilter,
	state_facade: Arc<StateFacade>,
	shielding_key_repo: Arc<ShieldingKeyRepository>,
	ocall_api: Arc<OCallApi>,
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
	Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	TopFilter: Filter<Value = TrustedOperation>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	OCallApi: EnclaveMetricsOCallApi + Send + Sync + 'static,
{
	/// Create new instance of Authoring API.
	pub fn new(
		top_pool: Arc<TopPool>,
		top_filter: TopFilter,
		state_facade: Arc<StateFacade>,
		encryption_key: Arc<ShieldingKeyRepository>,
		ocall_api: Arc<OCallApi>,
	) -> Self {
		Author { top_pool, top_filter, state_facade, shielding_key_repo: encryption_key, ocall_api }
	}
}

enum TopSubmissionMode {
	Submit,
	SubmitWatch,
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
	Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	TopFilter: Filter<Value = TrustedOperation>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	OCallApi: EnclaveMetricsOCallApi + Send + Sync + 'static,
{
	fn process_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
		submission_mode: TopSubmissionMode,
	) -> PoolFuture<TxHash<TopPool>, RpcError> {
		// check if shard exists
		match self.state_facade.shard_exists(&shard) {
			Err(_) => return Box::pin(ready(Err(ClientError::InvalidShard.into()))),
			Ok(shard_exists) =>
				if !shard_exists {
					return Box::pin(ready(Err(ClientError::InvalidShard.into())))
				},
		};

		// decrypt call
		let shielding_key = match self.shielding_key_repo.retrieve_key() {
			Ok(k) => k,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormatDecipher.into()))),
		};
		let request_vec = match shielding_key.decrypt(ext.as_slice()) {
			Ok(req) => req,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormatDecipher.into()))),
		};
		// decode call
		let trusted_operation = match TrustedOperation::decode(&mut request_vec.as_slice()) {
			Ok(op) => op,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
		};

		// apply top filter - return error if this specific type of trusted operation
		// is not allowed by the filter
		if !self.top_filter.filter(&trusted_operation) {
			return Box::pin(ready(Err(ClientError::UnsupportedOperation.into())))
		}

		//let best_block_hash = self.client.info().best_hash;
		// dummy block hash
		let best_block_hash = Default::default();

		// Update metric
		if let Err(e) = self.ocall_api.update_metric(EnclaveMetric::TopPoolSizeIncrement) {
			warn!("Failed to update metric for top pool size: {:?}", e);
		}

		if let Some(trusted_call_signed) = trusted_operation.to_call() {
			debug!(
				"Submitting trusted call to TOP pool: {:?}, TOP hash: {:?}",
				trusted_call_signed.call,
				self.hash_of(&trusted_operation)
			);
		} else if let TrustedOperation::get(Getter::trusted(ref trusted_getter_signed)) =
			trusted_operation
		{
			debug!(
				"Submitting trusted getter to TOP pool: {:?}, TOP hash: {:?}",
				trusted_getter_signed.getter,
				self.hash_of(&trusted_operation)
			);
		}

		match submission_mode {
			TopSubmissionMode::Submit => Box::pin(
				self.top_pool
					.submit_one(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						trusted_operation,
						shard,
					)
					.map_err(map_top_error::<TopPool>),
			),

			TopSubmissionMode::SubmitWatch => Box::pin(
				self.top_pool
					.submit_and_watch(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						trusted_operation,
						shard,
					)
					.map_err(map_top_error::<TopPool>),
			),
		}
	}

	fn remove_top(
		&self,
		bytes_or_hash: hash::TrustedOperationOrHash<TxHash<TopPool>>,
		shard: ShardIdentifier,
		inblock: bool,
	) -> Result<TxHash<TopPool>> {
		let hash = match bytes_or_hash {
			hash::TrustedOperationOrHash::Hash(h) => Ok(h),
			hash::TrustedOperationOrHash::OperationEncoded(bytes) => {
				match Decode::decode(&mut bytes.as_slice()) {
					Ok(op) => Ok(self.top_pool.hash_of(&op)),
					Err(e) => {
						error!("Failed to decode trusted operation: {:?}, operation will not be removed from pool", e);
						Err(StateRpcError::CodecError(e))
					},
				}
			},
			hash::TrustedOperationOrHash::Operation(op) => Ok(self.top_pool.hash_of(&op)),
		}?;

		debug!("removing {:?} from top pool", hash);

		// Update metric
		if let Err(e) = self.ocall_api.update_metric(EnclaveMetric::TopPoolSizeDecrement) {
			warn!("Failed to update metric for top pool size: {:?}", e);
		}

		let removed_op_hash = self
			.top_pool
			.remove_invalid(&[hash], shard, inblock)
			// Only remove a single element, so first should return Ok().
			.first()
			.map(|o| o.hash().clone())
			.ok_or(PoolError::InvalidTrustedOperation)?;

		Ok(removed_op_hash)
	}
}

fn map_top_error<P: TrustedOperationPool>(error: P::Error) -> RpcError {
	StateRpcError::PoolError(
		error
			.into_pool_error()
			.map(Into::into)
			.unwrap_or_else(|_error| PoolError::Verification),
	)
	.into()
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
	AuthorApi<TxHash<TopPool>, BlockHash<TopPool>>
	for Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	TopFilter: Filter<Value = TrustedOperation>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	OCallApi: EnclaveMetricsOCallApi + Send + Sync + 'static,
{
	fn submit_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<TopPool>, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::Submit)
	}

	/// Get hash of TrustedOperation
	fn hash_of(&self, xt: &TrustedOperation) -> TxHash<TopPool> {
		self.top_pool.hash_of(xt)
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		Ok(self.top_pool.ready(shard).map(|top| top.data().encode()).collect())
	}

	fn get_pending_trusted_getters(&self, shard: ShardIdentifier) -> Vec<TrustedOperation> {
		self.top_pool
			.ready(shard)
			.map(|o| o.data().clone())
			.into_iter()
			.filter(|o| matches!(o, TrustedOperation::get(Getter::trusted(_))))
			.collect()
	}

	fn get_pending_trusted_calls(&self, shard: ShardIdentifier) -> Vec<TrustedOperation> {
		self.top_pool
			.ready(shard)
			.map(|o| o.data().clone())
			.into_iter()
			.filter(|o| {
				matches!(o, TrustedOperation::direct_call(_))
					|| matches!(o, TrustedOperation::indirect_call(_))
			})
			.collect()
	}

	fn get_pending_trusted_calls_for(
		&self,
		shard: ShardIdentifier,
		account: &AccountId,
	) -> Vec<TrustedOperation> {
		self.get_pending_trusted_calls(shard)
			.into_iter()
			.filter(|o| o.signed_caller_account() == Some(account))
			.collect()
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		self.top_pool.shards()
	}

	fn list_handled_shards(&self) -> Vec<ShardIdentifier> {
		self.state_facade.list_shards().unwrap_or_default()
	}

	fn remove_calls_from_pool(
		&self,
		shard: ShardIdentifier,
		executed_calls: Vec<(hash::TrustedOperationOrHash<TxHash<TopPool>>, bool)>,
	) -> Vec<hash::TrustedOperationOrHash<TxHash<TopPool>>> {
		let mut failed_to_remove = Vec::new();
		for (executed_call, inblock) in executed_calls {
			if let Err(e) = self.remove_top(executed_call.clone(), shard, inblock) {
				// We don't want to return here before all calls have been iterated through,
				// hence log message and collect failed calls in vec.
				debug!("Error removing trusted call from top pool: {:?}", e);
				failed_to_remove.push(executed_call);
			}
		}
		failed_to_remove
	}

	fn watch_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<TopPool>, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::SubmitWatch)
	}
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi> OnBlockImported
	for Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	TopFilter: Filter<Value = TrustedOperation>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	OCallApi: EnclaveMetricsOCallApi + Send + Sync + 'static,
{
	type Hash = <TopPool as TrustedOperationPool>::Hash;

	fn on_block_imported(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash) {
		self.top_pool.on_block_imported(hashes, block_hash)
	}
}
