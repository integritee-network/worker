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

pub extern crate alloc;

use crate::{
	rpc::{
		author::client_error::Error as ClientError,
		error::{Error as StateRpcError, Result},
	},
	state::HandleState,
	top_pool::{
		error::{Error as PoolError, IntoPoolError},
		primitives::{
			BlockHash, InPoolOperation, PoolFuture, TrustedOperationPool, TrustedOperationSource,
			TxHash,
		},
	},
};
use alloc::boxed::Box;
use codec::{Decode, Encode};
use core::iter::Iterator;
use ita_stf::{Getter, ShardIdentifier, TrustedCallSigned, TrustedGetterSigned, TrustedOperation};
use itp_sgx_crypto::ShieldingCrypto;
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::{
	futures::future::{ready, TryFutureExt},
	Error as RpcError,
};
use log::*;
use sp_runtime::generic;
use std::{sync::Arc, vec::Vec};

pub mod atomic_container;
pub mod author_container;
pub mod author_tests;
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

/// Currently we treat all RPC operations as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such operations, so that the block authors can inject
/// some unique operations via RPC and have them included in the pool.
const TX_SOURCE: TrustedOperationSource = TrustedOperationSource::External;

/// Authoring API for RPC calls
///
///
pub struct Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
{
	top_pool: Arc<TopPool>,
	state_facade: Arc<StateFacade>,
	encryption_key: EncryptionKey,
}

impl<TopPool, StateFacade, EncryptionKey> Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
{
	/// Create new instance of Authoring API.
	pub fn new(
		top_pool: Arc<TopPool>,
		state_facade: Arc<StateFacade>,
		encryption_key: EncryptionKey,
	) -> Self {
		Author { top_pool, state_facade, encryption_key }
	}
}

enum TopSubmissionMode {
	Submit,
	SubmitWatch,
}

impl<TopPool, StateFacade, EncryptionKey> Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
{
	fn process_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
		submission_mode: TopSubmissionMode,
	) -> PoolFuture<TxHash<TopPool>, RpcError> {
		// check if shard already exists
		if !self.state_facade.exists(&shard) {
			//FIXME: Should this be an error? -> Issue error handling
			return Box::pin(ready(Err(ClientError::InvalidShard.into())))
		}

		// decrypt call
		let request_vec = match self.encryption_key.decrypt(&ext.as_slice()) {
			Ok(req) => req,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormatDecipher.into()))),
		};
		// decode call
		let stf_operation = match TrustedOperation::decode(&mut request_vec.as_slice()) {
			Ok(op) => op,
			Err(_) => return Box::pin(ready(Err(ClientError::BadFormat.into()))),
		};
		//let best_block_hash = self.client.info().best_hash;
		// dummy block hash
		let best_block_hash = Default::default();

		match submission_mode {
			TopSubmissionMode::Submit => Box::pin(
				self.top_pool
					.submit_one(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						stf_operation,
						shard,
					)
					.map_err(map_top_error::<TopPool>),
			),

			TopSubmissionMode::SubmitWatch => Box::pin(
				self.top_pool
					.submit_and_watch(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						stf_operation,
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

impl<TopPool, StateFacade, EncryptionKey> AuthorApi<TxHash<TopPool>, BlockHash<TopPool>>
	for Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
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
	) -> Result<(Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>)> {
		let mut calls: Vec<TrustedCallSigned> = vec![];
		let mut getters: Vec<TrustedGetterSigned> = vec![];
		for operation in self.top_pool.ready(shard) {
			match operation.data() {
				TrustedOperation::direct_call(call) => calls.push(call.clone()),
				TrustedOperation::get(getter) => match getter {
					Getter::trusted(trusted_getter_signed) =>
						getters.push(trusted_getter_signed.clone()),
					_ => error!("Found invalid trusted getter in top pool"),
				},
				_ => { // might be emtpy?
				},
			}
		}

		Ok((calls, getters))
	}

	fn get_shards(&self) -> Vec<ShardIdentifier> {
		self.top_pool.shards()
	}

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

impl<TopPool, StateFacade, EncryptionKey> OnBlockCreated
	for Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
{
	type Hash = <TopPool as TrustedOperationPool>::Hash;

	fn on_block_created(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash) {
		self.top_pool.on_block_created(hashes, block_hash)
	}
}

impl<TopPool, StateFacade, EncryptionKey> SendState for Author<TopPool, StateFacade, EncryptionKey>
where
	TopPool: TrustedOperationPool + Sync + Send + 'static,
	StateFacade: HandleState,
	EncryptionKey: ShieldingCrypto,
{
	type Hash = <TopPool as TrustedOperationPool>::Hash;

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> Result<()> {
		self.top_pool.rpc_send_state(hash, state_encoded).map_err(|e| e.into())
	}
}
