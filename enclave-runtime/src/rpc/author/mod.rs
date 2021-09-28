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

//! Substrate block-author/full-node API.
pub extern crate alloc;
use crate::{
	rpc::error::{Error as StateRpcError, Error, Result},
	state,
	top_pool::{
		error::{Error as PoolError, Error as TopPoolError, IntoPoolError},
		primitives::{
			BlockHash, InPoolOperation, PoolFuture, TrustedOperationPool, TrustedOperationSource,
			TxHash,
		},
		top_pool_container::GetTopPool,
	},
};
use alloc::{boxed::Box, vec::Vec};
use client_error::Error as ClientError;
use codec::{Decode, Encode};
use core::{iter::Iterator, ops::Deref};
use ita_stf::{Getter, ShardIdentifier, TrustedCallSigned, TrustedGetterSigned, TrustedOperation};
use itp_sgx_crypto::{Rsa3072Seal, ShieldingCrypto};
use itp_sgx_io::SealedIO;
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::{
	futures::future::{ready, TryFutureExt},
	Error as RpcError,
};
use log::*;
use sp_runtime::generic;
use std::sync::Arc;

pub mod client_error;
pub mod hash;

/// Substrate authoring RPC API
pub trait AuthorApi<Hash, BlockHash> {
	/// Submit encoded extrinsic for inclusion in block.
	fn submit_top(&self, extrinsic: Vec<u8>, shard: ShardIdentifier) -> PoolFuture<Hash, RpcError>;

	/// Return hash of Trusted Operation
	fn hash_of(&self, xt: &TrustedOperation) -> Result<Hash>;

	/// Returns all pending operations, potentially grouped by sender.
	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>>;

	/// Returns all pending operations divided in calls and getters, potentially grouped by sender.
	fn get_pending_tops_separated(
		&self,
		shard: ShardIdentifier,
	) -> Result<(Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>)>;

	fn get_shards(&self) -> Result<Vec<ShardIdentifier>>;

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

/// Authoring API
pub struct Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	top_pool_getter: Arc<TopPoolGetter>,
}

impl<TopPoolGetter> Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	/// Create new instance of Authoring API.
	pub fn new(top_pool_getter: Arc<TopPoolGetter>) -> Self {
		Author { top_pool_getter }
	}
}

/// Currently we treat all RPC operations as externals.
///
/// Possibly in the future we could allow opt-in for special treatment
/// of such operations, so that the block authors can inject
/// some unique operations via RPC and have them included in the pool.
const TX_SOURCE: TrustedOperationSource = TrustedOperationSource::External;

enum TopSubmissionMode {
	Submit,
	SubmitWatch,
}

impl<TopPoolGetter> Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	/// Execute a specific task or function on the TOP pool
	///
	/// Needed to get a clean way around the mutexes in which the pool are wrapped.
	/// Other approaches require lots of code duplication for the mutex locking and
	/// unwrapping.
	fn execute_on_top_pool<F, E, R>(&self, function_to_execute: F, mutex_error_func: E) -> R
	where
		F: FnOnce(&TopPoolGetter::TrustedOperationPool) -> R,
		E: FnOnce(Error) -> R,
	{
		let pool_mutex = match self.top_pool_getter.get() {
			Some(mutex) => mutex,
			None => {
				error!("Could not get mutex to trusted operation pool");
				return (mutex_error_func)(Error::PoolError(TopPoolError::UnlockError))
			},
		};

		let tx_pool_guard = pool_mutex.lock().unwrap();
		(function_to_execute)(tx_pool_guard.deref())
	}

	fn process_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
		submission_mode: TopSubmissionMode,
	) -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
		// check if shard already exists
		if !state::exists(&shard) {
			//FIXME: Should this be an error? -> Issue error handling
			return Box::pin(ready(Err(ClientError::InvalidShard.into())))
		}
		// decrypt call
		let rsa_key = Rsa3072Seal::unseal().unwrap();
		let request_vec = match rsa_key.decrypt(&ext.as_slice()) {
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
			TopSubmissionMode::Submit => self.execute_on_top_pool(
				|t: &TopPoolGetter::TrustedOperationPool| -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
					Box::pin(
						t.submit_one(
							&generic::BlockId::hash(best_block_hash),
							TX_SOURCE,
							stf_operation,
							shard,
						)
						.map_err(map_top_error::<TopPoolGetter::TrustedOperationPool>),
					)
				},
				|e| -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
						Box::pin(ready(Err(e.into())))
					},
			),

			TopSubmissionMode::SubmitWatch => self.execute_on_top_pool(
				|t: &TopPoolGetter::TrustedOperationPool| -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
					Box::pin(
					t.submit_and_watch(
						&generic::BlockId::hash(best_block_hash),
						TX_SOURCE,
						stf_operation,
						shard,
					)
					.map_err(map_top_error::<TopPoolGetter::TrustedOperationPool>)
					)
				},
				|e| -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
						Box::pin(ready(Err(e.into())))
					},
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

impl<TopPoolGetter>
	AuthorApi<
		TxHash<TopPoolGetter::TrustedOperationPool>,
		BlockHash<TopPoolGetter::TrustedOperationPool>,
	> for Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	fn submit_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::Submit)
	}

	/// Get hash of TrustedOperation
	fn hash_of(
		&self,
		xt: &TrustedOperation,
	) -> Result<TxHash<TopPoolGetter::TrustedOperationPool>> {
		self.execute_on_top_pool(|t| Ok(t.hash_of(xt)), Err)
	}

	fn pending_tops(&self, shard: ShardIdentifier) -> Result<Vec<Vec<u8>>> {
		self.execute_on_top_pool(
			|t| Ok(t.ready(shard).map(|top| top.data().encode()).collect()),
			Err,
		)
	}

	fn get_pending_tops_separated(
		&self,
		shard: ShardIdentifier,
	) -> Result<(Vec<TrustedCallSigned>, Vec<TrustedGetterSigned>)> {
		self.execute_on_top_pool(
			|t| {
				let mut calls: Vec<TrustedCallSigned> = vec![];
				let mut getters: Vec<TrustedGetterSigned> = vec![];
				for operation in t.ready(shard) {
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
			},
			Err,
		)
	}

	fn get_shards(&self) -> Result<Vec<ShardIdentifier>> {
		self.execute_on_top_pool(|t| Ok(t.shards()), Err)
	}

	fn remove_top(
		&self,
		bytes_or_hash: Vec<
			hash::TrustedOperationOrHash<TxHash<TopPoolGetter::TrustedOperationPool>>,
		>,
		shard: ShardIdentifier,
		inblock: bool,
	) -> Result<Vec<TxHash<TopPoolGetter::TrustedOperationPool>>> {
		self.execute_on_top_pool(
			|t| {
				let hashes = bytes_or_hash
					.into_iter()
					.map(|x| match x {
						hash::TrustedOperationOrHash::Hash(h) => Ok(h),
						hash::TrustedOperationOrHash::OperationEncoded(bytes) => {
							let op = Decode::decode(&mut &bytes[..]).unwrap();
							Ok(t.hash_of(&op))
						},
						hash::TrustedOperationOrHash::Operation(op) => Ok(t.hash_of(&op)),
					})
					.collect::<Result<Vec<_>>>()?;
				debug!("removing {:?} from top pool", hashes);

				Ok(t.remove_invalid(&hashes, shard, inblock)
					.into_iter()
					.map(|op| *op.hash())
					.collect())
			},
			Err,
		)
	}

	fn watch_top(
		&self,
		ext: Vec<u8>,
		shard: ShardIdentifier,
	) -> PoolFuture<TxHash<TopPoolGetter::TrustedOperationPool>, RpcError> {
		self.process_top(ext, shard, TopSubmissionMode::SubmitWatch)
	}
}

impl<TopPoolGetter> OnBlockCreated for Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	type Hash = <<TopPoolGetter as GetTopPool>::TrustedOperationPool as TrustedOperationPool>::Hash;

	fn on_block_created(&self, hashes: &[Self::Hash], block_hash: SidechainBlockHash) {
		self.execute_on_top_pool(
			|t| {
				t.on_block_created(hashes, block_hash);
			},
			|e| {
				error!("Failed to notify listeners about new block creation: {:?}", e);
			},
		);
	}
}

impl<TopPoolGetter> SendState for Author<TopPoolGetter>
where
	TopPoolGetter: GetTopPool + Sync + Send + 'static,
{
	type Hash = <<TopPoolGetter as GetTopPool>::TrustedOperationPool as TrustedOperationPool>::Hash;

	fn send_state(&self, hash: Self::Hash, state_encoded: Vec<u8>) -> Result<()> {
		self.execute_on_top_pool(
			|t| t.rpc_send_state(hash, state_encoded).map_err(|e| e.into()),
			Err,
		)
	}
}
