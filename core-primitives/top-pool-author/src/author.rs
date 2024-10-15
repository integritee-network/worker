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
use core::fmt::Debug;

use crate::{
	client_error::Error as ClientError,
	error::{Error as StateRpcError, Result},
	top_filter::Filter,
	traits::{AuthorApi, OnBlockImported},
};
use codec::{Decode, Encode};
use itp_sgx_crypto::{key_repository::AccessKey, ShieldingCryptoDecrypt};
use itp_stf_primitives::{
	traits::{PoolTransactionValidation, TrustedCallVerification},
	types::{AccountId, TrustedOperation as StfTrustedOperation, TrustedOperationOrHash},
};
use itp_stf_state_handler::query_shard_state::QueryShardState;
use itp_top_pool::{
	error::{Error as PoolError, IntoPoolError},
	primitives::{
		BlockHash, InPoolOperation, PoolFuture, PoolStatus, TrustedOperationPool,
		TrustedOperationSource, TxHash,
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
pub type AuthorTopFilter<TCS, G> = crate::top_filter::CallsOnlyFilter<TCS, G>;
#[cfg(feature = "offchain-worker")]
pub type AuthorTopFilter<TCS, G> = crate::top_filter::IndirectCallsOnlyFilter<TCS, G>;
#[cfg(feature = "teeracle")] // Teeracle currently does not process any trusted operations
pub type AuthorTopFilter<TCS, G> = crate::top_filter::DenyAllFilter<TCS, G>;

#[cfg(not(any(feature = "sidechain", feature = "offchain-worker", feature = "teeracle")))]
pub type AuthorTopFilter<TCS, G> = crate::top_filter::CallsOnlyFilter<TCS, G>;

/// Currently we treat all RPC operations as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such operations, so that the block authors can inject
/// some unique operations via RPC and have them included in the pool.
const TX_SOURCE: TrustedOperationSource = TrustedOperationSource::External;

/// Authoring API for RPC calls
///
///
pub struct Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
where
	TopPool: TrustedOperationPool<StfTrustedOperation<TCS, G>> + Sync + Send + 'static,
	TopFilter: Filter<Value = StfTrustedOperation<TCS, G>>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	TCS: PartialEq + Encode + Clone + Debug + Send + Sync,
	G: PartialEq + Encode + Clone + PoolTransactionValidation + Debug + Send + Sync,
{
	top_pool: Arc<TopPool>,
	top_filter: TopFilter,
	state_facade: Arc<StateFacade>,
	shielding_key_repo: Arc<ShieldingKeyRepository>,
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
	Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
where
	TopPool: TrustedOperationPool<StfTrustedOperation<TCS, G>> + Sync + Send + 'static,
	TopFilter: Filter<Value = StfTrustedOperation<TCS, G>>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	TCS: PartialEq + Encode + Clone + Debug + Send + Sync,
	G: PartialEq + Encode + Clone + PoolTransactionValidation + Debug + Send + Sync,
{
	/// Create new instance of Authoring API.
	pub fn new(
		top_pool: Arc<TopPool>,
		top_filter: TopFilter,
		state_facade: Arc<StateFacade>,
		encryption_key: Arc<ShieldingKeyRepository>,
	) -> Self {
		Author { top_pool, top_filter, state_facade, shielding_key_repo: encryption_key }
	}
}

enum TopSubmissionMode {
	Submit,
	SubmitWatch,
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
	Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
where
	TopPool: TrustedOperationPool<StfTrustedOperation<TCS, G>> + Sync + Send + 'static,
	TopFilter: Filter<Value = StfTrustedOperation<TCS, G>>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	TCS: PartialEq
		+ Encode
		+ Decode
		+ Clone
		+ Debug
		+ Send
		+ Sync
		+ TrustedCallVerification
		+ 'static,
	G: PartialEq
		+ Encode
		+ Decode
		+ Clone
		+ PoolTransactionValidation
		+ Debug
		+ Send
		+ Sync
		+ 'static,
{
	fn process_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
		submission_mode: TopSubmissionMode,
	) -> PoolFuture<TxHash, RpcError> {
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
		let trusted_operation =
			match StfTrustedOperation::<TCS, G>::decode(&mut request_vec.as_slice()) {
				Ok(op) => op,
				Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
			};

		trace!("decrypted indirect invocation: {:?}", trusted_operation);

		// apply top filter - return error if this specific type of trusted operation
		// is not allowed by the filter
		if !self.top_filter.filter(&trusted_operation) {
			warn!("unsupported operation");
			return Box::pin(ready(Err(ClientError::UnsupportedOperation.into())))
		}

		//let best_block_hash = self.client.info().best_hash;
		// dummy block hash
		let best_block_hash = Default::default();

		if let Some(trusted_call_signed) = trusted_operation.to_call() {
			debug!(
				"Submitting trusted call to TOP pool: {:?}, TOP hash: {:?}",
				trusted_call_signed,
				self.hash_of(&trusted_operation)
			);
		} else if let StfTrustedOperation::<TCS, G>::get(ref getter) = trusted_operation {
			debug!(
				"Submitting trusted or public getter to TOP pool: {:?}, TOP hash: {:?}",
				getter,
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
					.map_err(map_top_error::<TopPool, TCS, G>),
			),

			TopSubmissionMode::SubmitWatch => Box::pin(
				self.top_pool
					.submit_and_watch(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						trusted_operation,
						shard,
					)
					.map_err(map_top_error::<TopPool, TCS, G>),
			),
		}
	}

	fn remove_top(
		&self,
		bytes_or_hash: TrustedOperationOrHash<TCS, G>,
		shard: ShardIdentifier,
		inblock: bool,
	) -> Result<TxHash> {
		let hash = match bytes_or_hash {
			TrustedOperationOrHash::Hash(h) => Ok(h),
			TrustedOperationOrHash::OperationEncoded(bytes) => {
				match Decode::decode(&mut bytes.as_slice()) {
					Ok(op) => Ok(self.top_pool.hash_of(&op)),
					Err(e) => {
						error!("Failed to decode trusted operation: {:?}, operation will not be removed from pool", e);
						Err(StateRpcError::CodecError(e))
					},
				}
			},
			TrustedOperationOrHash::Operation(op) => Ok(self.top_pool.hash_of(&op)),
		}?;

		debug!("removing {:?} from top pool", hash);

		let removed_op_hash = self
			.top_pool
			.remove_invalid(&[hash], shard, inblock)
			// Only remove a single element, so first should return Ok().
			.first()
			.map(|o| o.hash())
			.ok_or(PoolError::InvalidTrustedOperation)?;

		Ok(removed_op_hash)
	}
}

fn map_top_error<P: TrustedOperationPool<StfTrustedOperation<TCS, G>>, TCS, G>(
	error: P::Error,
) -> RpcError
where
	TCS: PartialEq + Encode + Debug,
	G: PartialEq + Encode + Debug,
{
	StateRpcError::PoolError(
		error
			.into_pool_error()
			.map(Into::into)
			.unwrap_or_else(|_error| PoolError::Verification),
	)
	.into()
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
	AuthorApi<TxHash, BlockHash, TCS, G>
	for Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
where
	TopPool: TrustedOperationPool<StfTrustedOperation<TCS, G>> + Sync + Send + 'static,
	TopFilter: Filter<Value = StfTrustedOperation<TCS, G>>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	G: PartialEq
		+ Encode
		+ Decode
		+ Clone
		+ PoolTransactionValidation
		+ Debug
		+ Send
		+ Sync
		+ 'static,
	TCS: PartialEq
		+ Encode
		+ Decode
		+ Clone
		+ Debug
		+ Send
		+ Sync
		+ TrustedCallVerification
		+ 'static,
{
	fn submit_top(&self, ext: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<TxHash, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::Submit)
	}

	/// Get hash of TrustedOperation
	fn hash_of(&self, xt: &StfTrustedOperation<TCS, G>) -> TxHash {
		self.top_pool.hash_of(xt)
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		Ok(self.top_pool.ready(shard).map(|top| top.data().encode()).collect())
	}

	fn get_pending_getters(&self, shard: ShardIdentifier) -> Vec<StfTrustedOperation<TCS, G>> {
		self.top_pool
			.ready(shard)
			.map(|o| o.data().clone())
			.into_iter()
			.filter(|o| matches!(o, StfTrustedOperation::<TCS, G>::get(_)))
			.collect()
	}

	fn get_pending_trusted_calls(
		&self,
		shard: ShardIdentifier,
	) -> Vec<StfTrustedOperation<TCS, G>> {
		self.top_pool
			.ready(shard)
			.map(|o| o.data().clone())
			.into_iter()
			.filter(|o| {
				matches!(o, StfTrustedOperation::<TCS, G>::direct_call(_))
					|| matches!(o, StfTrustedOperation::<TCS, G>::indirect_call(_))
			})
			.collect()
	}

	fn get_status(&self, shard: ShardIdentifier) -> PoolStatus {
		self.top_pool.status(shard)
	}

	fn get_pending_trusted_calls_for(
		&self,
		shard: ShardIdentifier,
		account: &AccountId,
	) -> Vec<StfTrustedOperation<TCS, G>> {
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
		executed_calls: Vec<(TrustedOperationOrHash<TCS, G>, bool)>,
	) -> Vec<TrustedOperationOrHash<TCS, G>> {
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

	fn watch_top(&self, ext: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<TxHash, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::SubmitWatch)
	}
}

impl<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G> OnBlockImported
	for Author<TopPool, TopFilter, StateFacade, ShieldingKeyRepository, TCS, G>
where
	TopPool: TrustedOperationPool<StfTrustedOperation<TCS, G>> + Sync + Send + 'static,
	TopFilter: Filter<Value = StfTrustedOperation<TCS, G>>,
	StateFacade: QueryShardState,
	ShieldingKeyRepository: AccessKey,
	<ShieldingKeyRepository as AccessKey>::KeyType: ShieldingCryptoDecrypt,
	G: PartialEq + Encode + Clone + PoolTransactionValidation + Debug + Send + Sync,
	TCS: PartialEq + Encode + Clone + Debug + Send + Sync,
{
	type Hash = TxHash;

	fn on_block_imported(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash) {
		self.top_pool.on_block_imported(hashes, block_hash)
	}
}
