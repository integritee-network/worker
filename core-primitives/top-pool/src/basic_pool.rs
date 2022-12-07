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

pub extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use std::sync::Mutex;

use crate::{
	base_pool::TrustedOperation,
	error::IntoPoolError,
	pool::{ChainApi, ExtrinsicHash, Options as PoolOptions, Pool},
	primitives::{
		ImportNotificationStream, PoolFuture, PoolStatus, TrustedOperationPool,
		TrustedOperationSource, TxHash,
	},
};
use alloc::{boxed::Box, string::String, sync::Arc};
use core::pin::Pin;
use ita_stf::TrustedOperation as StfTrustedOperation;
use itc_direct_rpc_server::SendRpcResponse;
use itp_stf_primitives::types::ShardIdentifier;
use its_primitives::types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::{
	channel::oneshot,
	future::{ready, Future, FutureExt},
};
use sp_runtime::{
	generic::BlockId,
	traits::{Block as BlockT, NumberFor, Zero},
};
use std::{collections::HashMap, vec, vec::Vec};

type BoxedReadyIterator<Hash, Data> =
	Box<dyn Iterator<Item = Arc<TrustedOperation<Hash, Data>>> + Send>;

type ReadyIteratorFor<PoolApi> = BoxedReadyIterator<ExtrinsicHash<PoolApi>, StfTrustedOperation>;

type PolledIterator<PoolApi> = Pin<Box<dyn Future<Output = ReadyIteratorFor<PoolApi>> + Send>>;

struct ReadyPoll<T, Block: BlockT> {
	updated_at: NumberFor<Block>,
	pollers: Vec<(NumberFor<Block>, oneshot::Sender<T>)>,
}

impl<T, Block: BlockT> Default for ReadyPoll<T, Block> {
	fn default() -> Self {
		Self { updated_at: NumberFor::<Block>::zero(), pollers: Default::default() }
	}
}

impl<T, Block: BlockT> ReadyPoll<T, Block> {
	#[allow(unused)]
	fn trigger(&mut self, number: NumberFor<Block>, iterator_factory: impl Fn() -> T) {
		self.updated_at = number;

		let mut idx = 0;
		while idx < self.pollers.len() {
			if self.pollers[idx].0 <= number {
				let poller_sender = self.pollers.swap_remove(idx);
				let _ = poller_sender.1.send(iterator_factory());
			} else {
				idx += 1;
			}
		}
	}

	fn add(&mut self, number: NumberFor<Block>) -> oneshot::Receiver<T> {
		let (sender, receiver) = oneshot::channel();
		self.pollers.push((number, sender));
		receiver
	}

	fn updated_at(&self) -> NumberFor<Block> {
		self.updated_at
	}
}

/// Basic implementation of operation pool that can be customized by providing PoolApi.
pub struct BasicPool<PoolApi, Block, RpcResponse>
where
	Block: BlockT,
	PoolApi: ChainApi<Block = Block> + 'static,
	RpcResponse: SendRpcResponse<Hash = ExtrinsicHash<PoolApi>>,
{
	pool: Arc<Pool<PoolApi, RpcResponse>>,
	_api: Arc<PoolApi>,
	ready_poll: Arc<Mutex<ReadyPoll<ReadyIteratorFor<PoolApi>, Block>>>,
}

impl<PoolApi, Block, RpcResponse> BasicPool<PoolApi, Block, RpcResponse>
where
	Block: BlockT,
	PoolApi: ChainApi<Block = Block> + 'static,
	RpcResponse: SendRpcResponse<Hash = ExtrinsicHash<PoolApi>>,
{
	/// Create new basic operation pool with provided api and custom
	/// revalidation type.
	pub fn create(
		options: PoolOptions,
		pool_api: Arc<PoolApi>,
		rpc_response_sender: Arc<RpcResponse>,
		//prometheus: Option<&PrometheusRegistry>,
		//revalidation_type: RevalidationType,
		//spawner: impl SpawnNamed,
	) -> Self
	where
		<PoolApi as ChainApi>::Error: IntoPoolError,
	{
		let pool = Arc::new(Pool::new(options, pool_api.clone(), rpc_response_sender));
		BasicPool { _api: pool_api, pool, ready_poll: Default::default() }
	}
}

// FIXME: obey clippy
#[allow(clippy::type_complexity)]
impl<PoolApi, Block, RpcResponse> TrustedOperationPool for BasicPool<PoolApi, Block, RpcResponse>
where
	Block: BlockT,
	PoolApi: ChainApi<Block = Block> + 'static,
	<PoolApi as ChainApi>::Error: IntoPoolError,
	RpcResponse: SendRpcResponse<Hash = ExtrinsicHash<PoolApi>> + 'static,
{
	type Block = PoolApi::Block;
	type Hash = ExtrinsicHash<PoolApi>;
	type InPoolOperation = TrustedOperation<TxHash<Self>, StfTrustedOperation>;
	type Error = PoolApi::Error;

	fn submit_at(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		ops: Vec<StfTrustedOperation>,
		shard: ShardIdentifier,
	) -> PoolFuture<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error> {
		let pool = self.pool.clone();
		let at = *at;
		async move { pool.submit_at(&at, source, ops, shard).await }.boxed()
	}

	fn submit_one(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		op: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<Self>, Self::Error> {
		let pool = self.pool.clone();
		let at = *at;
		async move { pool.submit_one(&at, source, op, shard).await }.boxed()
	}

	fn submit_and_watch(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<Self>, Self::Error> {
		let at = *at;
		let pool = self.pool.clone();
		async move { pool.submit_and_watch(&at, source, xt, shard).await }.boxed()
	}

	fn ready_at(
		&self,
		at: NumberFor<Self::Block>,
		shard: ShardIdentifier,
	) -> PolledIterator<PoolApi> {
		if self.ready_poll.lock().unwrap().updated_at() >= at {
			let iterator: ReadyIteratorFor<PoolApi> =
				Box::new(self.pool.validated_pool().ready(shard));
			return Box::pin(ready(iterator))
		}

		Box::pin(self.ready_poll.lock().unwrap().add(at).map(|received| {
			received.unwrap_or_else(|e| {
				log::warn!("Error receiving pending set: {:?}", e);
				Box::new(vec![].into_iter())
			})
		}))
	}

	fn ready(&self, shard: ShardIdentifier) -> ReadyIteratorFor<PoolApi> {
		Box::new(self.pool.validated_pool().ready(shard))
	}

	fn shards(&self) -> Vec<ShardIdentifier> {
		self.pool.validated_pool().shards()
	}

	fn remove_invalid(
		&self,
		hashes: &[TxHash<Self>],
		shard: ShardIdentifier,
		inblock: bool,
	) -> Vec<Arc<Self::InPoolOperation>> {
		self.pool.validated_pool().remove_invalid(hashes, shard, inblock)
	}

	fn status(&self, shard: ShardIdentifier) -> PoolStatus {
		self.pool.validated_pool().status(shard)
	}

	fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>> {
		self.pool.validated_pool().import_notification_stream()
	}

	fn on_broadcasted(&self, propagations: HashMap<TxHash<Self>, Vec<String>>) {
		self.pool.validated_pool().on_broadcasted(propagations)
	}

	fn hash_of(&self, xt: &StfTrustedOperation) -> TxHash<Self> {
		self.pool.hash_of(xt)
	}

	fn ready_transaction(
		&self,
		hash: &TxHash<Self>,
		shard: ShardIdentifier,
	) -> Option<Arc<Self::InPoolOperation>> {
		self.pool.validated_pool().ready_by_hash(hash, shard)
	}

	fn on_block_imported(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash) {
		self.pool.validated_pool().on_block_imported(hashes, block_hash);
	}
}
