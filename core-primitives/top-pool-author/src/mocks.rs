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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::Result,
	traits::{AuthorApi, OnBlockImported},
};
use codec::{Decode, Encode};
use itp_stf_primitives::{
	traits::TrustedCallVerification,
	types::{AccountId, TrustedOperation as StfTrustedOperation, TrustedOperationOrHash},
};
use itp_top_pool::primitives::PoolFuture;
use itp_types::ShardIdentifier;
use jsonrpc_core::{futures::future::ready, Error as RpcError};
use sp_core::{blake2_256, H256};
use std::{boxed::Box, collections::HashMap, marker::PhantomData, vec, vec::Vec};

#[derive(Default)]
pub struct AuthorApiMock<Hash, BlockHash, TCS, G> {
	tops: RwLock<HashMap<ShardIdentifier, Vec<Vec<u8>>>>,
	_phantom: PhantomData<(Hash, BlockHash, TCS, G)>,
	pub remove_attempts: RwLock<usize>,
}

impl<Hash, BlockHash, TCS, G> AuthorApiMock<Hash, BlockHash, TCS, G>
where
	TCS: Encode + Decode + Debug + Send + Sync + TrustedCallVerification,
	G: Encode + Decode + Debug + Send + Sync,
{
	fn remove_top(
		&self,
		bytes_or_hash: Vec<TrustedOperationOrHash<TCS, G>>,
		shard: ShardIdentifier,
		_inblock: bool,
	) -> Result<Vec<H256>> {
		let hashes = bytes_or_hash
			.into_iter()
			.map(|x| match x {
				TrustedOperationOrHash::Hash(h) => h,
				TrustedOperationOrHash::OperationEncoded(bytes) => {
					let top: StfTrustedOperation<TCS, G> =
						StfTrustedOperation::<TCS, G>::decode(&mut bytes.as_slice()).unwrap();
					top.hash()
				},
				TrustedOperationOrHash::Operation(op) => op.hash(),
			})
			.collect::<Vec<_>>();

		let mut tops_lock = self.tops.write().unwrap();

		match tops_lock.get_mut(&shard) {
			Some(tops_encoded) => {
				let removed_tops = tops_encoded
					.drain_filter(|t| hashes.contains(&blake2_256(t).into()))
					.map(|t| blake2_256(&t).into())
					.collect::<Vec<_>>();
				Ok(removed_tops)
			},
			None => Ok(Vec::new()),
		}
	}
}

impl<TCS, G> AuthorApi<H256, H256, TCS, G> for AuthorApiMock<H256, H256, TCS, G>
where
	TCS: Encode + Decode + Debug + Clone + TrustedCallVerification + Send + Sync,
	G: Encode + Decode + Debug + Clone + Send + Sync,
{
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<H256, RpcError> {
		let mut write_lock = self.tops.write().unwrap();
		let extrinsics = write_lock.entry(shard).or_default();
		extrinsics.push(extrinsic);
		Box::pin(ready(Ok(H256::default())))
	}

	fn hash_of(&self, xt: &StfTrustedOperation<TCS, G>) -> H256 {
		xt.hash()
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		let extrinsics = self.tops.read().unwrap().get(&shard).cloned();
		Ok(extrinsics.unwrap_or_default())
	}

	fn get_pending_getters(&self, shard: ShardIdentifier) -> Vec<StfTrustedOperation<TCS, G>> {
		self.tops
			.read()
			.unwrap()
			.get(&shard)
			.map(|encoded_operations| {
				let mut trusted_getters: Vec<StfTrustedOperation<TCS, G>> = Vec::new();
				for encoded_operation in encoded_operations {
					if let Ok(g) = G::decode(&mut encoded_operation.as_slice()) {
						trusted_getters.push(StfTrustedOperation::<TCS, G>::get(g));
					}
				}
				trusted_getters
			})
			.unwrap_or_default()
	}

	fn get_pending_trusted_calls(
		&self,
		shard: ShardIdentifier,
	) -> Vec<StfTrustedOperation<TCS, G>> {
		self.tops
			.read()
			.unwrap()
			.get(&shard)
			.map(|encoded_operations| {
				let mut trusted_operations: Vec<StfTrustedOperation<TCS, G>> = Vec::new();
				for encoded_operation in encoded_operations {
					if let Ok(o) = TCS::decode(&mut encoded_operation.as_slice()) {
						trusted_operations.push(StfTrustedOperation::direct_call(o));
					}
				}
				trusted_operations
			})
			.unwrap_or_default()
	}

	fn get_pending_trusted_calls_for(
		&self,
		shard: ShardIdentifier,
		account: &AccountId,
	) -> Vec<StfTrustedOperation<TCS, G>> {
		self.tops
			.read()
			.unwrap()
			.get(&shard)
			.map(|encoded_operations| {
				let mut trusted_operations: Vec<StfTrustedOperation<TCS, G>> = Vec::new();
				for encoded_operation in encoded_operations {
					if let Ok(o) = TCS::decode(&mut encoded_operation.as_slice()) {
						let top = StfTrustedOperation::direct_call(o);
						if top.signed_caller_account() == Some(account) {
							trusted_operations.push(top);
						}
					}
				}
				trusted_operations
			})
			.unwrap_or_default()
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		self.tops.read().unwrap().keys().cloned().collect()
	}

	fn list_handled_shards(&self) -> Vec<ShardIdentifier> {
		//dummy
		self.tops.read().unwrap().keys().cloned().collect()
	}

	fn remove_calls_from_pool(
		&self,
		shard: ShardIdentifier,
		executed_calls: Vec<(TrustedOperationOrHash<TCS, G>, bool)>,
	) -> Vec<TrustedOperationOrHash<TCS, G>> {
		let mut remove_attempts_lock = self.remove_attempts.write().unwrap();
		*remove_attempts_lock += 1;

		let mut failed_to_remove = Vec::new();
		for (executed_call, inblock) in executed_calls {
			if self.remove_top(vec![executed_call.clone()], shard, inblock).is_err() {
				failed_to_remove.push(executed_call);
			}
		}
		failed_to_remove
	}

	fn watch_top(&self, _ext: Vec<u8>, _shard: ShardIdentifier) -> PoolFuture<H256, RpcError> {
		todo!()
	}
}

impl<TCS, G> OnBlockImported for AuthorApiMock<H256, H256, TCS, G> {
	type Hash = H256;

	fn on_block_imported(&self, _hashes: &[Self::Hash], _block_hash: H256) {}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::test_fixtures::shard_id;
	use codec::Encode;
	use futures::executor::block_on;
	use itp_test::mock::stf_mock::TrustedCallSignedMock;
	use std::vec;

	#[test]
	fn submitted_tops_can_be_removed_again() {
		let author = AuthorApiMock::<H256, H256, TrustedCallSignedMock, GetterMock>::default();
		let shard = shard_id();
		let trusted_operation = TrustedOperationMock::indirect_call(TrustedCallSignedMock);

		let _ = block_on(author.submit_top(trusted_operation.encode(), shard)).unwrap();

		assert_eq!(1, author.pending_tops(shard).unwrap().len());
		assert_eq!(1, author.get_pending_trusted_calls(shard).len());
		assert_eq!(0, author.get_pending_getters(shard).len());

		let trusted_operation_or_hash =
			TrustedOperationOrHash::<TrustedCallSignedMock, GetterMock>::from_top(
				trusted_operation.clone(),
			);
		let removed_tops = author.remove_top(vec![trusted_operation_or_hash], shard, true).unwrap();

		assert_eq!(1, removed_tops.len());
		assert!(author.tops.read().unwrap().get(&shard).unwrap().is_empty());
	}
}
