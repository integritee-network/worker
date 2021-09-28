// This file is part of Substrate.

// Copyright (C) 2017-2020 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::{rpc::error::Result, top_pool::primitives::PoolFuture};
use ita_stf::{ShardIdentifier, TrustedCallSigned, TrustedGetterSigned, TrustedOperation};
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::Error as RpcError;
use std::vec::Vec;

pub mod atomic_container;
pub mod author;
pub mod author_container;
pub mod client_error;
pub mod hash;

/// Substrate authoring RPC API
pub trait AuthorApi<Hash, BlockHash> {
	/// Submit encoded extrinsic for inclusion in block.
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError>;

	/// Return hash of Trusted Operation
	fn hash_of(&self, xt: &TrustedOperation) -> Hash;

	/// Returns all pending operations, potentially grouped by sender.
	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>>;

	/// Returns all pending operations divided in calls and getters, potentially grouped by sender.
	fn get_pending_tops_separated(
		&self,
		shard: ShardIdentifier,
	) -> Result<(Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>)>;

	fn get_shards(&self) -> Vec<ShardIdentifier>;

	/// Remove given call from the pool and temporarily ban it to prevent reimporting.
	fn remove_top(
		&self,
		bytes_or_hash: Vec<hash::TrustedOperationOrHash<Hash>>,
		shard: ShardIdentifier,
		inblock: bool,
	) -> Result<Vec<Hash>>;

	/// Submit an extrinsic to watch.
	///
	/// See [`TrustedOperationStatus`](sp_transaction_pool::TrustedOperationStatus) for details on transaction
	/// life cycle.
	fn watch_top(&self, ext: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError>;
}

/// Trait to send state of a trusted getter back to the client
pub trait SendState {
	type Hash;

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> Result<()>;
}

/// Trait to notify listeners/observer of a newly created block
pub trait OnBlockCreated {
	type Hash;

	fn on_block_created(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash);
}
