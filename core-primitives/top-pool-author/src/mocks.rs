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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{error::Result, traits::AuthorApi};
use codec::Decode;
use ita_stf::{
	hash::{Hash, TrustedOperationOrHash},
	TrustedGetterSigned, TrustedOperation,
};
use itp_top_pool::primitives::PoolFuture;
use itp_types::ShardIdentifier;
use jsonrpc_core::{futures_util::future::ready, Error as RpcError};
use sp_core::{blake2_256, H256};
use std::{collections::HashMap, marker::PhantomData, vec::Vec};

#[derive(Default)]
pub struct AuthorApiMock<Hash, BlockHash> {
	tops: RwLock<HashMap<ShardIdentifier, Vec<Vec<u8>>>>,
	_phantom: PhantomData<(Hash, BlockHash)>,
}

impl<Hash, BlockHash> AuthorApiMock<Hash, BlockHash> {
	fn decode_trusted_operation(mut encoded_operation: &[u8]) -> Option<TrustedOperation> {
		TrustedOperation::decode(&mut encoded_operation).ok()
	}

	fn decode_trusted_getter_signed(mut encoded_operation: &[u8]) -> Option<TrustedGetterSigned> {
		TrustedGetterSigned::decode(&mut encoded_operation).ok()
	}
}

impl AuthorApi<H256, H256> for AuthorApiMock<H256, H256> {
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<H256, RpcError> {
		let mut write_lock = self.tops.write().unwrap();
		let extrinsics = write_lock.entry(shard).or_default();
		extrinsics.push(extrinsic);
		Box::pin(ready(Ok(H256::default())))
	}

	fn hash_of(&self, xt: &TrustedOperation) -> H256 {
		xt.hash()
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		let extrinsics = self.tops.read().unwrap().get(&shard).cloned();
		Ok(extrinsics.unwrap_or_default())
	}

	fn get_pending_tops_separated(
		&self,
		shard: ShardIdentifier,
	) -> Result<(Vec<TrustedOperation>, Vec<TrustedGetterSigned>)> {
		// This assumes the trusted operations are only encoded, not encrypted.
		// (which differs from the 'real' implementation, but makes testing easier)
		Ok(self
			.tops
			.read()
			.unwrap()
			.get(&shard)
			.map(|encoded_operations| {
				let mut trusted_operations: Vec<TrustedOperation> = Vec::new();
				let mut trusted_getters: Vec<TrustedGetterSigned> = Vec::new();

				for encoded_operation in encoded_operations {
					if let Some(o) = Self::decode_trusted_operation(encoded_operation) {
						trusted_operations.push(o);
					} else if let Some(g) = Self::decode_trusted_getter_signed(encoded_operation) {
						trusted_getters.push(g)
					}
				}

				(trusted_operations, trusted_getters)
			})
			.unwrap_or_default())
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		self.tops.read().unwrap().keys().cloned().collect()
	}

	fn remove_top(
		&self,
		bytes_or_hash: Vec<TrustedOperationOrHash<H256>>,
		shard: ShardIdentifier,
		_inblock: bool,
	) -> crate::error::Result<Vec<H256>> {
		let hashes = bytes_or_hash
			.into_iter()
			.map(|x| match x {
				TrustedOperationOrHash::Hash(h) => h,
				TrustedOperationOrHash::OperationEncoded(bytes) => {
					let op: TrustedOperation = Decode::decode(&mut bytes.as_slice()).unwrap();
					op.hash()
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

	fn watch_top(&self, _ext: Vec<u8>, _shard: ShardIdentifier) -> PoolFuture<H256, RpcError> {
		todo!()
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::test_fixtures::{create_indirect_trusted_operation, shard_id};
	use codec::Encode;
	use futures::executor::block_on;
	use std::vec;

	#[test]
	fn submitted_tops_can_be_removed_again() {
		let author = AuthorApiMock::<H256, H256>::default();
		let shard = shard_id();
		let trusted_operation = create_indirect_trusted_operation();

		let _ = block_on(author.submit_top(trusted_operation.encode(), shard)).unwrap();

		assert_eq!(1, author.pending_tops(shard).unwrap().len());
		assert_eq!(1, author.get_pending_tops_separated(shard).unwrap().0.len());
		assert_eq!(0, author.get_pending_tops_separated(shard).unwrap().1.len());

		let trusted_operation_or_hash = TrustedOperationOrHash::from_top(trusted_operation.clone());
		let removed_tops = author.remove_top(vec![trusted_operation_or_hash], shard, true).unwrap();

		assert_eq!(1, removed_tops.len());
		assert!(author.tops.read().unwrap().get(&shard).unwrap().is_empty());
	}
}
