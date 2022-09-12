/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	base_pool::TrustedOperation,
	error::Error,
	primitives::{
		ImportNotificationStream, PoolFuture, PoolStatus, TrustedOperationPool,
		TrustedOperationSource, TxHash,
	},
};
use codec::Encode;
use core::{future::Future, pin::Pin};
use ita_stf::TrustedOperation as StfTrustedOperation;
use itp_types::{Block, BlockHash as SidechainBlockHash, ShardIdentifier, H256};
use jsonrpc_core::futures::future::ready;
use sp_runtime::{
	generic::BlockId,
	traits::{BlakeTwo256, Hash, NumberFor},
};
use std::{boxed::Box, collections::HashMap, string::String, sync::Arc, vec, vec::Vec};

/// Mock for the trusted operation pool
///
/// To be used in unit tests
pub struct TrustedOperationPoolMock {
	submitted_transactions: RwLock<HashMap<ShardIdentifier, TxPayload>>,
}

/// Transaction payload
#[derive(Clone, PartialEq)]
pub struct TxPayload {
	pub block_id: BlockId<<TrustedOperationPoolMock as TrustedOperationPool>::Block>,
	pub source: TrustedOperationSource,
	pub xts: Vec<StfTrustedOperation>,
	pub shard: ShardIdentifier,
}

impl Default for TrustedOperationPoolMock {
	fn default() -> Self {
		TrustedOperationPoolMock { submitted_transactions: RwLock::new(HashMap::new()) }
	}
}

impl TrustedOperationPoolMock {
	pub fn get_last_submitted_transactions(&self) -> HashMap<ShardIdentifier, TxPayload> {
		let transactions = self.submitted_transactions.read().unwrap();
		transactions.clone()
	}

	fn map_stf_top_to_tx(
		stf_top: &StfTrustedOperation,
	) -> Arc<TrustedOperation<TxHash<Self>, StfTrustedOperation>> {
		Arc::new(TrustedOperation::<TxHash<Self>, StfTrustedOperation> {
			data: stf_top.clone(),
			bytes: 0,
			hash: hash_of_top(stf_top),
			priority: 0u64,
			valid_till: 0u64,
			requires: vec![],
			provides: vec![],
			propagate: false,
			source: TrustedOperationSource::External,
		})
	}
}

impl TrustedOperationPool for TrustedOperationPoolMock {
	type Block = Block;
	type Hash = H256;
	type InPoolOperation = TrustedOperation<TxHash<Self>, StfTrustedOperation>;
	type Error = Error;

	#[allow(clippy::type_complexity)]
	fn submit_at(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		xts: Vec<StfTrustedOperation>,
		shard: ShardIdentifier,
	) -> PoolFuture<Vec<Result<TxHash<Self>, Self::Error>>, Self::Error> {
		let mut transactions = self.submitted_transactions.write().unwrap();
		transactions.insert(shard, TxPayload { block_id: *at, source, xts: xts.clone(), shard });

		let top_hashes: Vec<Result<TxHash<Self>, Self::Error>> =
			xts.iter().map(|top| Ok(hash_of_top(top))).collect();

		Box::pin(ready(Ok(top_hashes)))
	}

	fn submit_one(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<Self>, Self::Error> {
		let mut transactions = self.submitted_transactions.write().unwrap();
		transactions
			.insert(shard, TxPayload { block_id: *at, source, xts: vec![xt.clone()], shard });

		let top_hash = hash_of_top(&xt);

		Box::pin(ready(Ok(top_hash)))
	}

	fn submit_and_watch(
		&self,
		at: &BlockId<Self::Block>,
		source: TrustedOperationSource,
		xt: StfTrustedOperation,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<Self>, Self::Error> {
		self.submit_one(at, source, xt, shard)
	}

	#[allow(clippy::type_complexity)]
	fn ready_at(
		&self,
		_at: NumberFor<Self::Block>,
		_shard: ShardIdentifier,
	) -> Pin<
		Box<
			dyn Future<Output = Box<dyn Iterator<Item = Arc<Self::InPoolOperation>> + Send>> + Send,
		>,
	> {
		unimplemented!()
	}

	#[allow(clippy::type_complexity)]
	fn ready(
		&self,
		shard: ShardIdentifier,
	) -> Box<dyn Iterator<Item = Arc<Self::InPoolOperation>> + Send> {
		let transactions = self.submitted_transactions.read().unwrap();
		let ready_transactions = transactions
			.get(&shard)
			.map(|payload| payload.xts.iter().map(Self::map_stf_top_to_tx).collect())
			.unwrap_or_else(Vec::new);
		Box::new(ready_transactions.into_iter())
	}

	fn shards(&self) -> Vec<ShardIdentifier> {
		let transactions = self.submitted_transactions.read().unwrap();
		transactions.iter().map(|(shard, _)| *shard).collect()
	}

	fn remove_invalid(
		&self,
		_hashes: &[TxHash<Self>],
		_shard: ShardIdentifier,
		_inblock: bool,
	) -> Vec<Arc<Self::InPoolOperation>> {
		Vec::new()
	}

	fn status(&self, shard: ShardIdentifier) -> PoolStatus {
		let transactions = self.submitted_transactions.read().unwrap();
		transactions
			.get(&shard)
			.map(|payload| PoolStatus {
				ready: payload.xts.len(),
				ready_bytes: 0,
				future: 0,
				future_bytes: 0,
			})
			.unwrap_or_else(default_pool_status)
	}

	fn import_notification_stream(&self) -> ImportNotificationStream<TxHash<Self>> {
		unimplemented!()
	}

	fn on_broadcasted(&self, _propagations: HashMap<TxHash<Self>, Vec<String>>) {
		unimplemented!()
	}

	fn hash_of(&self, xt: &StfTrustedOperation) -> TxHash<Self> {
		hash_of_top(xt)
	}

	fn ready_transaction(
		&self,
		_hash: &TxHash<Self>,
		_shard: ShardIdentifier,
	) -> Option<Arc<Self::InPoolOperation>> {
		unimplemented!()
	}

	fn on_block_imported(&self, _hashes: &[Self::Hash], _block_hash: SidechainBlockHash) {}
}

fn default_pool_status() -> PoolStatus {
	PoolStatus { ready: 0, ready_bytes: 0, future: 0, future_bytes: 0 }
}

fn hash_of_top(top: &StfTrustedOperation) -> H256 {
	top.using_encoded(|x| BlakeTwo256::hash(x))
}
