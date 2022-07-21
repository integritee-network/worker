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
	traits::{AuthorApi, OnBlockImported, SendState},
};
use codec::{Decode, Encode};
use ita_stf::{hash, Getter, TrustedGetterSigned, TrustedOperation};
use itp_enclave_metrics::EnclaveMetric;
use itp_ocall_api::EnclaveMetricsOCallApi;
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt};
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
use std::{boxed::Box, sync::Arc, vec, vec::Vec};

/// Define type of TOP filter that is used in the Author
#[cfg(feature = "sidechain")]
pub type AuthorTopFilter = crate::top_filter::AllowAllTopsFilter;
#[cfg(feature = "offchain-worker")]
pub type AuthorTopFilter = crate::top_filter::NoDirectCallsFilter;

#[cfg(not(any(feature = "sidechain", feature = "offchain-worker")))]
pub type AuthorTopFilter = crate::top_filter::AllowAllTopsFilter;

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

	fn get_pending_tops_separated(
		&self,
		shard: ShardIdentifier,
	) -> Result<(Vec<TrustedOperation>, Vec<TrustedGetterSigned>)> {
		let mut calls: Vec<TrustedOperation> = vec![];
		let mut getters: Vec<TrustedGetterSigned> = vec![];
		for operation in self.top_pool.ready(shard) {
			match operation.data() {
				TrustedOperation::direct_call(_) => calls.push(operation.data().clone()),
				TrustedOperation::indirect_call(_) => calls.push(operation.data().clone()),
				TrustedOperation::get(getter) => match getter {
					Getter::trusted(trusted_getter_signed) =>
						getters.push(trusted_getter_signed.clone()),
					_ => error!("Found invalid trusted getter in top pool"),
				},
			}
		}

		Ok((calls, getters))
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		self.top_pool.shards()
	}

	// FIXME: Fix the "inblock" variable such that multiple inputs are allowed (& rename to remove_tops?)
	fn remove_top(
		&self,
		bytes_or_hash: Vec<hash::TrustedOperationOrHash<TxHash<TopPool>>>,
		shard: ShardIdentifier,
		inblock: bool,
	) -> Result<Vec<TxHash<TopPool>>> {
		let hashes = bytes_or_hash
			.into_iter()
			.map(|x| match x {
				hash::TrustedOperationOrHash::Hash(h) => Ok(h),
				hash::TrustedOperationOrHash::OperationEncoded(bytes) => {
					let op = Decode::decode(&mut &bytes[..]).unwrap();
					Ok(self.top_pool.hash_of(&op))
				},
				hash::TrustedOperationOrHash::Operation(op) => Ok(self.top_pool.hash_of(&op)),
			})
			.collect::<Result<Vec<_>>>()?;
		debug!("removing {:?} from top pool", hashes);

		// Update metric
		if let Err(e) = self.ocall_api.update_metric(EnclaveMetric::TopPoolSizeDecrement) {
			warn!("Failed to update metric for top pool size: {:?}", e);
		}

		Ok(self
			.top_pool
			.remove_invalid(&hashes, shard, inblock)
			.into_iter()
			.map(|op| op.hash().clone())
			.collect())
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

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, OCallApi> SendState
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

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> Result<()> {
		self.top_pool.rpc_send_state(hash, state_encoded).map_err(|e| e.into())
	}
}
