// This file is part of Substrate.

// Copyright (C) 2018-2020 Parity Technologies (UK) Ltd.
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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxMutex as Mutex;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::Mutex;
#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	base_pool as base,
	base_pool::PruneStatus,
	error,
	listener::Listener,
	pool::{ChainApi, EventStream, ExtrinsicHash, Options, TransactionFor},
	primitives::{PoolStatus, TrustedOperationSource},
	rotator::PoolRotator,
};
use codec::Encode;
use core::{hash, result::Result};
use ita_stf::TrustedOperation as StfTrustedOperation;
use itc_direct_rpc_server::SendRpcResponse;
use itp_stf_primitives::types::ShardIdentifier;
use itp_types::BlockHash as SidechainBlockHash;
use jsonrpc_core::futures::channel::mpsc::{channel, Sender};
use sp_runtime::{
	generic::BlockId,
	traits::{self, SaturatedConversion},
	transaction_validity::{TransactionTag as Tag, ValidTransaction},
};
use std::{
	collections::{HashMap, HashSet},
	format,
	string::String,
	sync::Arc,
	time::Instant,
	vec,
	vec::Vec,
};

/// Pre-validated operation. Validated pool only accepts operations wrapped in this enum.
#[derive(Debug)]
pub enum ValidatedOperation<Hash, Ex, Error> {
	/// TrustedOperation that has been validated successfully.
	Valid(base::TrustedOperation<Hash, Ex>),
	/// TrustedOperation that is invalid.
	Invalid(Hash, Error),
	/// TrustedOperation which validity can't be determined.
	///
	/// We're notifying watchers about failure, if 'unknown' operation is submitted.
	Unknown(Hash, Error),
}

impl<Hash, Ex, Error> ValidatedOperation<Hash, Ex, Error> {
	/// Consume validity result, operation data and produce ValidTransaction.
	pub fn valid_at(
		at: u64,
		hash: Hash,
		source: TrustedOperationSource,
		data: Ex,
		bytes: usize,
		validity: ValidTransaction,
	) -> Self {
		Self::Valid(base::TrustedOperation {
			data,
			bytes,
			hash,
			source,
			priority: validity.priority,
			requires: validity.requires,
			provides: validity.provides,
			propagate: validity.propagate,
			valid_till: at.saturated_into::<u64>().saturating_add(validity.longevity),
		})
	}
}

/// A type of validated operation stored in the pool.
pub type ValidatedOperationFor<B> =
	ValidatedOperation<ExtrinsicHash<B>, StfTrustedOperation, <B as ChainApi>::Error>;

/// Pool that deals with validated operations.
pub struct ValidatedPool<B: ChainApi, R: SendRpcResponse>
where
	R: SendRpcResponse<Hash = ExtrinsicHash<B>>,
{
	api: Arc<B>,
	options: Options,
	listener: RwLock<Listener<ExtrinsicHash<B>, R>>,
	pool: RwLock<base::BasePool<ExtrinsicHash<B>, StfTrustedOperation>>,
	import_notification_sinks: Mutex<Vec<Sender<ExtrinsicHash<B>>>>,
	rotator: PoolRotator<ExtrinsicHash<B>>,
}

impl<B: ChainApi, R> ValidatedPool<B, R>
where
	R: SendRpcResponse<Hash = ExtrinsicHash<B>>,
{
	/// Create a new operation pool.
	pub fn new(options: Options, api: Arc<B>, rpc_response_sender: Arc<R>) -> Self {
		let base_pool = base::BasePool::new(options.reject_future_operations);
		ValidatedPool {
			options,
			listener: RwLock::new(Listener::new(rpc_response_sender)),
			api,
			pool: RwLock::new(base_pool),
			import_notification_sinks: Default::default(),
			rotator: Default::default(),
		}
	}

	/// Bans given set of hashes.
	pub fn ban(&self, now: &Instant, hashes: impl IntoIterator<Item = ExtrinsicHash<B>>) {
		self.rotator.ban(now, hashes)
	}

	/// Returns true if operation with given hash is currently banned from the pool.
	pub fn is_banned(&self, hash: &ExtrinsicHash<B>) -> bool {
		self.rotator.is_banned(hash)
	}

	/// A fast check before doing any further processing of a operation, like validation.
	///
	/// If `ingore_banned` is `true`, it will not check if the operation is banned.
	///
	/// It checks if the operation is already imported or banned. If so, it returns an error.
	pub fn check_is_known(
		&self,
		tx_hash: &ExtrinsicHash<B>,
		ignore_banned: bool,
		shard: ShardIdentifier,
	) -> Result<(), B::Error> {
		if !ignore_banned && self.is_banned(tx_hash) {
			Err(error::Error::TemporarilyBanned.into())
		} else if self.pool.read().unwrap().is_imported(tx_hash, shard) {
			Err(error::Error::AlreadyImported.into())
		} else {
			Ok(())
		}
	}

	/// Imports a bunch of pre-validated operations to the pool.
	pub fn submit(
		&self,
		txs: impl IntoIterator<Item = ValidatedOperationFor<B>>,
		shard: ShardIdentifier,
	) -> Vec<Result<ExtrinsicHash<B>, B::Error>> {
		let results = txs
			.into_iter()
			.map(|validated_tx| self.submit_one(validated_tx, shard))
			.collect::<Vec<_>>();

		// only enforce limits if there is at least one imported operation
		let removed = if results.iter().any(|res| res.is_ok()) {
			self.enforce_limits(shard)
		} else {
			Default::default()
		};

		results
			.into_iter()
			.map(|res| match res {
				Ok(ref hash) if removed.contains(hash) =>
					Err(error::Error::ImmediatelyDropped.into()),
				other => other,
			})
			.collect()
	}

	/// Submit single pre-validated operation to the pool.
	fn submit_one(
		&self,
		tx: ValidatedOperationFor<B>,
		shard: ShardIdentifier,
	) -> Result<ExtrinsicHash<B>, B::Error> {
		match tx {
			ValidatedOperation::Valid(tx) => {
				let imported =
					self.pool.write().map_err(|_| error::Error::UnlockError)?.import(tx, shard)?;

				if let base::Imported::Ready { ref hash, .. } = imported {
					self.import_notification_sinks
						.lock()
						.map_err(|_| error::Error::UnlockError)?
						.retain_mut(|sink| match sink.try_send(*hash) {
							Ok(()) => true,
							Err(e) =>
								if e.is_full() {
									log::warn!(target: "txpool", "[{:?}] Trying to notify an import but the channel is full", hash);
									true
								} else {
									false
								},
						});
				}

				let mut listener = self.listener.write().map_err(|_| error::Error::UnlockError)?;
				fire_events(&mut listener, &imported);
				Ok(*imported.hash())
			},
			ValidatedOperation::Invalid(hash, err) => {
				self.rotator.ban(&Instant::now(), core::iter::once(hash));
				Err(err)
			},
			ValidatedOperation::Unknown(hash, err) => {
				self.listener.write().unwrap().invalid(&hash);
				Err(err)
			},
		}
	}

	fn enforce_limits(&self, shard: ShardIdentifier) -> HashSet<ExtrinsicHash<B>> {
		let status = self.pool.read().unwrap().status(shard);
		let ready_limit = &self.options.ready;
		let future_limit = &self.options.future;

		log::debug!(target: "txpool", "Pool Status: {:?}", status);
		if ready_limit.is_exceeded(status.ready, status.ready_bytes)
			|| future_limit.is_exceeded(status.future, status.future_bytes)
		{
			log::debug!(
				target: "txpool",
				"Enforcing limits ({}/{}kB ready, {}/{}kB future",
				ready_limit.count, ready_limit.total_bytes / 1024,
				future_limit.count, future_limit.total_bytes / 1024,
			);

			// clean up the pool
			let removed = {
				let mut pool = self.pool.write().unwrap();
				let removed = pool
					.enforce_limits(ready_limit, future_limit, shard)
					.into_iter()
					.map(|x| x.hash)
					.collect::<HashSet<_>>();
				// ban all removed operations
				self.rotator.ban(&Instant::now(), removed.iter().copied());
				removed
			};
			if !removed.is_empty() {
				log::debug!(target: "txpool", "Enforcing limits: {} dropped", removed.len());
			}

			// run notifications
			let mut listener = self.listener.write().unwrap();
			for h in &removed {
				listener.dropped(h, None);
			}

			removed
		} else {
			Default::default()
		}
	}

	/// Import a single extrinsic and starts to watch their progress in the pool.
	pub fn submit_and_watch(
		&self,
		tx: ValidatedOperationFor<B>,
		shard: ShardIdentifier,
	) -> Result<ExtrinsicHash<B>, B::Error> {
		match tx {
			ValidatedOperation::Valid(tx) => {
				let hash_result = self
					.submit(core::iter::once(ValidatedOperation::Valid(tx)), shard)
					.pop()
					.expect("One extrinsic passed; one result returned; qed");
				// TODO: How to return / notice if Future or Ready queue?
				if let Ok(hash) = hash_result {
					self.listener.write().unwrap().create_watcher(hash);
				}
				hash_result
			},
			ValidatedOperation::Invalid(hash, err) => {
				self.rotator.ban(&Instant::now(), core::iter::once(hash));
				Err(err)
			},
			ValidatedOperation::Unknown(_, err) => Err(err),
		}
	}

	/// Resubmits revalidated operations back to the pool.
	///
	/// Removes and then submits passed operations and all dependent operations.
	/// Transactions that are missing from the pool are not submitted.
	pub fn resubmit(
		&self,
		mut updated_transactions: HashMap<ExtrinsicHash<B>, ValidatedOperationFor<B>>,
		shard: ShardIdentifier,
	) {
		#[derive(Debug, Clone, Copy, PartialEq)]
		enum Status {
			Future,
			Ready,
			Failed,
			Dropped,
		}

		let (mut initial_statuses, final_statuses) = {
			let mut pool = self.pool.write().unwrap();

			// remove all passed operations from the ready/future queues
			// (this may remove additional operations as well)
			//
			// for every operation that has an entry in the `updated_transactions`,
			// we store updated validation result in txs_to_resubmit
			// for every operation that has no entry in the `updated_transactions`,
			// we store last validation result (i.e. the pool entry) in txs_to_resubmit
			let mut initial_statuses = HashMap::new();
			let mut txs_to_resubmit = Vec::with_capacity(updated_transactions.len());
			while !updated_transactions.is_empty() {
				let hash = updated_transactions
					.keys()
					.next()
					.cloned()
					.expect("operations is not empty; qed");

				// note we are not considering tx with hash invalid here - we just want
				// to remove it along with dependent operations and `remove_subtree()`
				// does exactly what we need
				let removed = pool.remove_subtree(&[hash], shard);
				for removed_tx in removed {
					let removed_hash = removed_tx.hash;
					let updated_transaction = updated_transactions.remove(&removed_hash);
					let tx_to_resubmit = if let Some(updated_tx) = updated_transaction {
						updated_tx
					} else {
						// in most cases we'll end up in successful `try_unwrap`, but if not
						// we still need to reinsert operation back to the pool => duplicate call
						let operation = match Arc::try_unwrap(removed_tx) {
							Ok(operation) => operation,
							Err(operation) => operation.duplicate(),
						};
						ValidatedOperation::Valid(operation)
					};

					initial_statuses.insert(removed_hash, Status::Ready);
					txs_to_resubmit.push((removed_hash, tx_to_resubmit));
				}
				// make sure to remove the hash even if it's not present in the pool any more.
				updated_transactions.remove(&hash);
			}

			// if we're rejecting future operations, then insertion order matters here:
			// if tx1 depends on tx2, then if tx1 is inserted before tx2, then it goes
			// to the future queue and gets rejected immediately
			// => let's temporary stop rejection and clear future queue before return
			pool.with_futures_enabled(|pool, reject_future_operations| {
				// now resubmit all removed operations back to the pool
				let mut final_statuses = HashMap::new();
				for (hash, tx_to_resubmit) in txs_to_resubmit {
					match tx_to_resubmit {
						ValidatedOperation::Valid(tx) => match pool.import(tx, shard) {
							Ok(imported) => match imported {
								base::Imported::Ready { promoted, failed, removed, .. } => {
									final_statuses.insert(hash, Status::Ready);
									for hash in promoted {
										final_statuses.insert(hash, Status::Ready);
									}
									for hash in failed {
										final_statuses.insert(hash, Status::Failed);
									}
									for tx in removed {
										final_statuses.insert(tx.hash, Status::Dropped);
									}
								},
								base::Imported::Future { .. } => {
									final_statuses.insert(hash, Status::Future);
								},
							},
							Err(err) => {
								// we do not want to fail if single operation import has failed
								// nor we do want to propagate this error, because it could tx unknown to caller
								// => let's just notify listeners (and issue debug message)
								log::warn!(
									target: "txpool",
									"[{:?}] Removing invalid operation from update: {:?}",
									hash,
									err,
								);
								final_statuses.insert(hash, Status::Failed);
							},
						},
						ValidatedOperation::Invalid(_, _) | ValidatedOperation::Unknown(_, _) => {
							final_statuses.insert(hash, Status::Failed);
						},
					}
				}

				// if the pool is configured to reject future operations, let's clear the future
				// queue, updating final statuses as required
				if reject_future_operations {
					for future_tx in pool.clear_future(shard) {
						final_statuses.insert(future_tx.hash, Status::Dropped);
					}
				}

				(initial_statuses, final_statuses)
			})
		};

		// and now let's notify listeners about status changes
		let mut listener = self.listener.write().unwrap();
		for (hash, final_status) in final_statuses {
			let initial_status = initial_statuses.remove(&hash);
			if initial_status.is_none() || Some(final_status) != initial_status {
				match final_status {
					Status::Future => listener.future(&hash),
					Status::Ready => listener.ready(&hash, None),
					Status::Dropped => listener.dropped(&hash, None),
					Status::Failed => listener.invalid(&hash),
				}
			}
		}
	}

	/// For each extrinsic, returns tags that it provides (if known), or None (if it is unknown).
	pub fn extrinsics_tags(
		&self,
		hashes: &[ExtrinsicHash<B>],
		shard: ShardIdentifier,
	) -> Vec<Option<Vec<Tag>>> {
		self.pool
			.read()
			.unwrap()
			.by_hashes(hashes, shard)
			.into_iter()
			.map(|existing_in_pool| existing_in_pool.map(|operation| operation.provides.to_vec()))
			.collect()
	}

	/// Get ready operation by hash
	pub fn ready_by_hash(
		&self,
		hash: &ExtrinsicHash<B>,
		shard: ShardIdentifier,
	) -> Option<TransactionFor<B>> {
		self.pool.read().unwrap().ready_by_hash(hash, shard)
	}

	/// Prunes ready operations that provide given list of tags.
	pub fn prune_tags(
		&self,
		tags: impl IntoIterator<Item = Tag>,
		shard: ShardIdentifier,
	) -> Result<PruneStatus<ExtrinsicHash<B>, StfTrustedOperation>, B::Error> {
		// Perform tag-based pruning in the base pool
		let status = self.pool.write().unwrap().prune_tags(tags, shard);
		// Notify event listeners of all operations
		// that were promoted to `Ready` or were dropped.
		{
			let mut listener = self.listener.write().unwrap();
			for promoted in &status.promoted {
				fire_events(&mut *listener, promoted);
			}
			for f in &status.failed {
				listener.dropped(f, None);
			}
		}

		Ok(status)
	}

	/// Resubmit operations that have been revalidated after prune_tags call.
	pub fn resubmit_pruned(
		&self,
		at: &BlockId<B::Block>,
		known_imported_hashes: impl IntoIterator<Item = ExtrinsicHash<B>> + Clone,
		pruned_hashes: Vec<ExtrinsicHash<B>>,
		pruned_xts: Vec<ValidatedOperationFor<B>>,
		shard: ShardIdentifier,
	) -> Result<(), B::Error>
	where
		<B as ChainApi>::Error: error::IntoPoolError,
	{
		debug_assert_eq!(pruned_hashes.len(), pruned_xts.len());

		// Resubmit pruned operations
		let results = self.submit(pruned_xts, shard);

		// Collect the hashes of operations that now became invalid (meaning that they are successfully pruned).
		let hashes = results.into_iter().enumerate().filter_map(|(idx, r)| {
			match r.map_err(error::IntoPoolError::into_pool_error) {
				Err(Ok(error::Error::InvalidTrustedOperation)) => Some(pruned_hashes[idx]),
				_ => None,
			}
		});
		// Fire `pruned` notifications for collected hashes and make sure to include
		// `known_imported_hashes` since they were just imported as part of the block.
		let hashes = hashes.chain(known_imported_hashes.into_iter());
		self.fire_pruned(at, hashes)?;

		// perform regular cleanup of old operations in the pool
		// and update temporary bans.
		self.clear_stale(at, shard)?;
		Ok(())
	}

	/// Fire notifications for pruned operations.
	pub fn fire_pruned(
		&self,
		at: &BlockId<B::Block>,
		hashes: impl Iterator<Item = ExtrinsicHash<B>>,
	) -> Result<(), B::Error> {
		let header_hash = self
			.api
			.block_id_to_hash(at)?
			.ok_or_else(|| error::Error::InvalidBlockId(format!("{:?}", at)))?;
		let mut listener = self.listener.write().unwrap();
		let mut set = HashSet::with_capacity(hashes.size_hint().0);
		for h in hashes {
			// `hashes` has possibly duplicate hashes.
			// we'd like to send out the `InBlock` notification only once.
			if !set.contains(&h) {
				listener.pruned(header_hash, &h);
				set.insert(h);
			}
		}
		Ok(())
	}

	/// Removes stale operations from the pool.
	///
	/// Stale operations are operation beyond their longevity period.
	/// Note this function does not remove operations that are already included in the chain.
	/// See `prune_tags` if you want this.
	pub fn clear_stale(
		&self,
		at: &BlockId<B::Block>,
		shard: ShardIdentifier,
	) -> Result<(), B::Error> {
		let block_number = self
			.api
			.block_id_to_number(at)?
			.ok_or_else(|| error::Error::InvalidBlockId(format!("{:?}", at)))?
			.saturated_into::<u64>();
		let now = Instant::now();
		let to_remove = {
			self.ready(shard)
				.filter(|tx| self.rotator.ban_if_stale(&now, block_number, tx))
				.map(|tx| tx.hash)
				.collect::<Vec<_>>()
		};
		let futures_to_remove: Vec<ExtrinsicHash<B>> = {
			let p = self.pool.read().unwrap();
			let mut hashes = Vec::new();
			for tx in p.futures(shard) {
				if self.rotator.ban_if_stale(&now, block_number, tx) {
					hashes.push(tx.hash);
				}
			}
			hashes
		};
		// removing old operations
		self.remove_invalid(&to_remove, shard, false);
		self.remove_invalid(&futures_to_remove, shard, false);
		// clear banned operations timeouts
		self.rotator.clear_timeouts(&now);

		Ok(())
	}

	/// Get rotator reference.
	/// only used for test
	pub fn rotator(&self) -> &PoolRotator<ExtrinsicHash<B>> {
		&self.rotator
	}

	/// Get api reference.
	pub fn api(&self) -> &B {
		&self.api
	}

	/// Return an event stream of notifications for when operations are imported to the pool.
	///
	/// Consumers of this stream should use the `ready` method to actually get the
	/// pending operations in the right order.
	pub fn import_notification_stream(&self) -> EventStream<ExtrinsicHash<B>> {
		const CHANNEL_BUFFER_SIZE: usize = 1024;

		let (sink, stream) = channel(CHANNEL_BUFFER_SIZE);
		self.import_notification_sinks.lock().unwrap().push(sink);
		stream
	}

	/// Invoked when extrinsics are broadcasted.
	pub fn on_broadcasted(&self, propagated: HashMap<ExtrinsicHash<B>, Vec<String>>) {
		let mut listener = self.listener.write().unwrap();
		for (hash, peers) in propagated.into_iter() {
			listener.broadcasted(&hash, peers);
		}
	}

	/// Remove a subtree of operations from the pool and mark them invalid.
	///
	/// The operations passed as an argument will be additionally banned
	/// to prevent them from entering the pool right away.
	/// Note this is not the case for the dependent operations - those may
	/// still be valid so we want to be able to re-import them.
	pub fn remove_invalid(
		&self,
		hashes: &[ExtrinsicHash<B>],
		shard: ShardIdentifier,
		inblock: bool,
	) -> Vec<TransactionFor<B>> {
		// early exit in case there is no invalid operations.
		if hashes.is_empty() {
			return vec![]
		}

		let invalid = self.pool.write().unwrap().remove_subtree(hashes, shard);

		log::debug!(target: "txpool", "Removed invalid operations: {:?}", invalid);

		let mut listener = self.listener.write().unwrap();
		if inblock {
			for _tx in &invalid {
				//listener.in_block(&tx.hash);
			}
		} else {
			// temporarily ban invalid operations
			self.rotator.ban(&Instant::now(), hashes.iter().cloned());
			for tx in &invalid {
				listener.invalid(&tx.hash);
			}
		}

		invalid
	}

	/// Get an iterator for ready operations ordered by priority
	pub fn ready(&self, shard: ShardIdentifier) -> impl Iterator<Item = TransactionFor<B>> + Send {
		self.pool.read().unwrap().ready(shard)
	}

	/// Get an iterator for all shards
	pub fn shards(&self) -> Vec<ShardIdentifier> {
		let mut shards = vec![];
		let base_pool = self.pool.read().unwrap();
		let shard_iterator = base_pool.get_shards();
		for shard in shard_iterator {
			shards.push(*shard);
		}
		shards
	}

	/// Returns pool status.
	pub fn status(&self, shard: ShardIdentifier) -> PoolStatus {
		self.pool.read().unwrap().status(shard)
	}

	/// Notify all watchers that operations in the block with hash have been finalized
	pub async fn on_block_finalized(&self, block_hash: SidechainBlockHash) -> Result<(), B::Error>
	where
		<<B as ChainApi>::Block as sp_runtime::traits::Block>::Hash: core::fmt::Display,
	{
		log::trace!(target: "txpool", "Attempting to notify watchers of finalization for {}", block_hash);
		self.listener.write().unwrap().finalized(block_hash);
		Ok(())
	}

	/// Notify the listener of retracted blocks
	pub fn on_block_retracted(&self, block_hash: SidechainBlockHash) {
		self.listener.write().unwrap().retracted(block_hash)
	}

	/// Notify the listener of top inclusion in sidechain block
	pub fn on_block_imported(&self, hashes: &[ExtrinsicHash<B>], block_hash: SidechainBlockHash) {
		for top_hash in hashes.iter() {
			self.listener.write().unwrap().in_block(top_hash, block_hash);
		}
	}
}

fn fire_events<H, R, Ex>(listener: &mut Listener<H, R>, imported: &base::Imported<H, Ex>)
where
	H: hash::Hash + Eq + traits::Member + Encode, // + Serialize,
	R: SendRpcResponse<Hash = H>,
{
	match *imported {
		base::Imported::Ready { ref promoted, ref failed, ref removed, ref hash } => {
			listener.ready(hash, None);
			for f in failed {
				listener.invalid(f);
			}
			for r in removed {
				listener.dropped(&r.hash, Some(hash));
			}
			for p in promoted {
				listener.ready(p, None);
			}
		},
		base::Imported::Future { ref hash } => listener.future(hash),
	}
}
