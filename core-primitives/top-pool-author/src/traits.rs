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

use crate::error::Result;
use ita_stf::{hash, TrustedOperation};
use itp_stf_primitives::types::AccountId;
use itp_top_pool::primitives::PoolFuture;
use itp_types::{BlockHash as SidechainBlockHash, ShardIdentifier, H256};
use jsonrpc_core::Error as RpcError;
use std::vec::Vec;

/// Trait alias for a full STF author API
pub trait FullAuthor = AuthorApi<H256, H256> + OnBlockImported<Hash = H256> + Send + Sync + 'static;

/// Authoring RPC API
pub trait AuthorApi<Hash, BlockHash> {
	/// Submit encoded extrinsic for inclusion in block.
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError>;

	/// Return hash of Trusted Operation
	fn hash_of(&self, xt: &TrustedOperation) -> Hash;

	/// Returns all pending operations, potentially grouped by sender.
	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>>;

	/// Returns all pending trusted getters.
	fn get_pending_trusted_getters(&self, shard: ShardIdentifier) -> Vec<TrustedOperation>;

	/// Returns all pending trusted calls.
	fn get_pending_trusted_calls(&self, shard: ShardIdentifier) -> Vec<TrustedOperation>;

	/// Returns all pending trusted calls for a given `account`
	fn get_pending_trusted_calls_for(
		&self,
		shard: ShardIdentifier,
		account: &AccountId,
	) -> Vec<TrustedOperation>;

	/// returns all shards which are currently present in the tops in the pool
	fn get_shards(&self) -> Vec<ShardIdentifier>;

	/// returns all shards which are handled by our worker
	fn list_handled_shards(&self) -> Vec<ShardIdentifier>;

	/// Remove a collection of trusted operations from the pool.
	/// Return operations that were not successfully removed.
	fn remove_calls_from_pool(
		&self,
		shard: ShardIdentifier,
		executed_calls: Vec<(hash::TrustedOperationOrHash<Hash>, bool)>,
	) -> Vec<hash::TrustedOperationOrHash<Hash>>;

	/// Submit an extrinsic to watch.
	///
	/// See [`TrustedOperationStatus`](sp_transaction_pool::TrustedOperationStatus) for details on transaction
	/// life cycle.
	fn watch_top(&self, ext: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError>;
}

/// Trait to notify listeners/observer of a newly created block
pub trait OnBlockImported {
	type Hash;

	fn on_block_imported(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash);
}
