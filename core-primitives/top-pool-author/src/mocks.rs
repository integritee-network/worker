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
use ita_stf::{hash::TrustedOperationOrHash, TrustedGetterSigned, TrustedOperation};
use itp_top_pool::primitives::PoolFuture;
use itp_types::ShardIdentifier;
use jsonrpc_core::{futures_util::future::ready, Error as RpcError};
use std::{collections::HashMap, marker::PhantomData, vec::Vec};

#[derive(Default)]
pub struct AuthorApiMock<Hash, BlockHash> {
	tops: RwLock<HashMap<ShardIdentifier, Vec<Vec<u8>>>>,
	_phantom: PhantomData<(Hash, BlockHash)>,
}

impl<Hash, BlockHash> AuthorApi<Hash, BlockHash> for AuthorApiMock<Hash, BlockHash>
where
	Hash: Default + Send + Sync + 'static,
{
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError> {
		let mut write_lock = self.tops.write().unwrap();
		let extrinsics = write_lock.entry(shard).or_default();
		extrinsics.push(extrinsic);
		Box::pin(ready(Ok(Hash::default())))
	}

	fn hash_of(&self, _xt: &TrustedOperation) -> Hash {
		Hash::default()
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		let extrinsics = self.tops.read().unwrap().get(&shard).cloned();
		Ok(extrinsics.unwrap_or_default())
	}

	fn get_pending_tops_separated(
		&self,
		_shard: ShardIdentifier,
	) -> Result<(Vec<TrustedOperation>, Vec<TrustedGetterSigned>)> {
		todo!()
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		todo!()
	}

	fn remove_top(
		&self,
		_bytes_or_hash: Vec<TrustedOperationOrHash<Hash>>,
		_shard: ShardIdentifier,
		_inblock: bool,
	) -> crate::error::Result<Vec<Hash>> {
		todo!()
	}

	fn watch_top(&self, _ext: Vec<u8>, _shard: ShardIdentifier) -> PoolFuture<Hash, RpcError> {
		todo!()
	}
}
