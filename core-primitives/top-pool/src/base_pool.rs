// This file is part of Substrate.

// Copyright (C) 2018-2021 Parity Technologies (UK) Ltd.
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

//! A basic version of the dependency graph.
//!
//! For a more full-featured pool, have a look at the `pool` module.

pub extern crate alloc;
use crate::{
	error,
	future::{FutureTrustedOperations, WaitingTrustedOperations},
	primitives::{InPoolOperation, PoolStatus, TrustedOperationSource as Source},
	ready::ReadyOperations,
};
use alloc::{fmt, sync::Arc, vec, vec::Vec};
use core::{hash, iter};
use itp_stf_primitives::types::ShardIdentifier;
use log::{debug, trace, warn};
use sp_core::hexdisplay::HexDisplay;
use sp_runtime::{
	traits::Member,
	transaction_validity::{
		TransactionLongevity as Longevity, TransactionPriority as Priority, TransactionTag as Tag,
	},
};
use std::collections::HashSet;

/// Successful import result.
#[derive(Debug, PartialEq, Eq)]
pub enum Imported<Hash, Ex> {
	/// TrustedOperation was successfully imported to Ready queue.
	Ready {
		/// Hash of operation that was successfully imported.
		hash: Hash,
		/// operations that got promoted from the Future queue.
		promoted: Vec<Hash>,
		/// operations that failed to be promoted from the Future queue and are now discarded.
		failed: Vec<Hash>,
		/// operations removed from the Ready pool (replaced).
		removed: Vec<Arc<TrustedOperation<Hash, Ex>>>,
	},
	/// TrustedOperation was successfully imported to Future queue.
	Future {
		/// Hash of operation that was successfully imported.
		hash: Hash,
	},
}

impl<Hash, Ex> Imported<Hash, Ex> {
	/// Returns the hash of imported operation.
	pub fn hash(&self) -> &Hash {
		use self::Imported::*;
		match *self {
			Ready { ref hash, .. } => hash,
			Future { ref hash, .. } => hash,
		}
	}
}

/// Status of pruning the queue.
#[derive(Debug)]
pub struct PruneStatus<Hash, Ex> {
	/// A list of imports that satisfying the tag triggered.
	pub promoted: Vec<Imported<Hash, Ex>>,
	/// A list of operations that failed to be promoted and now are discarded.
	pub failed: Vec<Hash>,
	/// A list of operations that got pruned from the ready queue.
	pub pruned: Vec<Arc<TrustedOperation<Hash, Ex>>>,
}

/// Immutable operation
#[derive(PartialEq, Eq, Clone)]
pub struct TrustedOperation<Hash, Extrinsic> {
	/// Raw extrinsic representing that operation.
	pub data: Extrinsic,
	/// Number of bytes encoding of the operation requires.
	pub bytes: usize,
	/// TrustedOperation hash (unique)
	pub hash: Hash,
	/// TrustedOperation priority (higher = better)
	pub priority: Priority,
	/// At which block the operation becomes invalid?
	pub valid_till: Longevity,
	/// Tags required by the operation.
	pub requires: Vec<Tag>,
	/// Tags that this operation provides.
	pub provides: Vec<Tag>,
	/// Should that operation be propagated.
	pub propagate: bool,
	/// Source of that operation.
	pub source: Source,
}

impl<Hash, Extrinsic> AsRef<Extrinsic> for TrustedOperation<Hash, Extrinsic> {
	fn as_ref(&self) -> &Extrinsic {
		&self.data
	}
}

impl<Hash, Extrinsic> InPoolOperation for TrustedOperation<Hash, Extrinsic> {
	type TrustedOperation = Extrinsic;
	type Hash = Hash;

	fn data(&self) -> &Extrinsic {
		&self.data
	}

	fn hash(&self) -> &Hash {
		&self.hash
	}

	fn priority(&self) -> &Priority {
		&self.priority
	}

	fn longevity(&self) -> &Longevity {
		&self.valid_till
	}

	fn requires(&self) -> &[Tag] {
		&self.requires
	}

	fn provides(&self) -> &[Tag] {
		&self.provides
	}

	fn is_propagable(&self) -> bool {
		self.propagate
	}
}

impl<Hash: Clone, Extrinsic: Clone> TrustedOperation<Hash, Extrinsic> {
	/// Explicit operation clone.
	///
	/// TrustedOperation should be cloned only if absolutely necessary && we want
	/// every reason to be commented. That's why we `TrustedOperation` is not `Clone`,
	/// but there's explicit `duplicate` method.
	pub fn duplicate(&self) -> Self {
		TrustedOperation {
			data: self.data.clone(),
			bytes: self.bytes,
			hash: self.hash.clone(),
			priority: self.priority,
			source: self.source,
			valid_till: self.valid_till,
			requires: self.requires.clone(),
			provides: self.provides.clone(),
			propagate: self.propagate,
		}
	}
}

impl<Hash, Extrinsic> fmt::Debug for TrustedOperation<Hash, Extrinsic>
where
	Hash: fmt::Debug,
	Extrinsic: fmt::Debug,
{
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		fn print_tags(fmt: &mut fmt::Formatter, tags: &[Tag]) -> fmt::Result {
			let mut it = tags.iter();
			if let Some(t) = it.next() {
				write!(fmt, "{}", HexDisplay::from(t))?;
			}
			for t in it {
				write!(fmt, ",{}", HexDisplay::from(t))?;
			}
			Ok(())
		}

		write!(fmt, "TrustedOperation {{ ")?;
		write!(fmt, "hash: {:?}, ", &self.hash)?;
		write!(fmt, "priority: {:?}, ", &self.priority)?;
		write!(fmt, "valid_till: {:?}, ", &self.valid_till)?;
		write!(fmt, "bytes: {:?}, ", &self.bytes)?;
		write!(fmt, "propagate: {:?}, ", &self.propagate)?;
		write!(fmt, "source: {:?}, ", &self.source)?;
		write!(fmt, "requires: [")?;
		print_tags(fmt, &self.requires)?;
		write!(fmt, "], provides: [")?;
		print_tags(fmt, &self.provides)?;
		write!(fmt, "], ")?;
		write!(fmt, "data: {:?}", &self.data)?;
		write!(fmt, "}}")?;
		Ok(())
	}
}

/// Store last pruned tags for given number of invocations.
const RECENTLY_PRUNED_TAGS: usize = 2;

/// TrustedOperation pool.
///
/// Builds a dependency graph for all operations in the pool and returns
/// the ones that are currently ready to be executed.
///
/// General note:
/// If function returns some operations it usually means that importing them
/// as-is for the second time will fail or produce unwanted results.
/// Most likely it is required to revalidate them and recompute set of
/// required tags.
#[derive(Debug)]
pub struct BasePool<Hash: hash::Hash + Eq + Ord, Ex> {
	reject_future_operations: bool,
	future: FutureTrustedOperations<Hash, Ex>,
	ready: ReadyOperations<Hash, Ex>,
	/// Store recently pruned tags (for last two invocations).
	///
	/// This is used to make sure we don't accidentally put
	/// operations to future in case they were just stuck in verification.
	recently_pruned: [HashSet<Tag>; RECENTLY_PRUNED_TAGS],
	recently_pruned_index: usize,
}

impl<Hash: hash::Hash + Member + Ord, Ex: fmt::Debug> Default for BasePool<Hash, Ex> {
	fn default() -> Self {
		Self::new(false)
	}
}

impl<Hash: hash::Hash + Member + Ord, Ex: fmt::Debug> BasePool<Hash, Ex> {
	/// Create new pool given reject_future_operations flag.
	pub fn new(reject_future_operations: bool) -> Self {
		BasePool {
			reject_future_operations,
			future: Default::default(),
			ready: Default::default(),
			recently_pruned: Default::default(),
			recently_pruned_index: 0,
		}
	}

	/// Temporary enables future operations, runs closure and then restores
	/// `reject_future_operations` flag back to previous value.
	///
	/// The closure accepts the mutable reference to the pool and original value
	/// of the `reject_future_operations` flag.
	pub(crate) fn with_futures_enabled<T>(
		&mut self,
		closure: impl FnOnce(&mut Self, bool) -> T,
	) -> T {
		let previous = self.reject_future_operations;
		self.reject_future_operations = false;
		let return_value = closure(self, previous);
		self.reject_future_operations = previous;
		return_value
	}

	/// Returns if the operation for the given hash is already imported.
	pub fn is_imported(&self, tx_hash: &Hash, shard: ShardIdentifier) -> bool {
		self.future.contains(tx_hash, shard) || self.ready.contains(tx_hash, shard)
	}

	/// Imports operations to the pool.
	///
	/// The pool consists of two parts: Future and Ready.
	/// The former contains operations that require some tags that are not yet provided by
	/// other operations in the pool.
	/// The latter contains operations that have all the requirements satisfied and are
	/// ready to be included in the block.
	pub fn import(
		&mut self,
		tx: TrustedOperation<Hash, Ex>,
		shard: ShardIdentifier,
	) -> error::Result<Imported<Hash, Ex>> {
		if self.is_imported(&tx.hash, shard) {
			return Err(error::Error::AlreadyImported)
		}

		let tx = WaitingTrustedOperations::new(
			tx,
			self.ready.provided_tags(shard),
			&self.recently_pruned,
		);
		trace!(target: "txpool", "[{:?}] {:?}", tx.operation.hash, tx);
		debug!(
			target: "txpool",
			"[{:?}] Importing to {}",
			tx.operation.hash,
			if tx.is_ready() { "ready" } else { "future" }
		);

		// If all tags are not satisfied import to future.
		if !tx.is_ready() {
			if self.reject_future_operations {
				return Err(error::Error::RejectedFutureTrustedOperation)
			}

			let hash = tx.operation.hash.clone();
			self.future.import(tx, shard);
			return Ok(Imported::Future { hash })
		}

		self.import_to_ready(tx, shard)
	}

	/// Imports operations to ready queue.
	///
	/// NOTE the operation has to have all requirements satisfied.
	fn import_to_ready(
		&mut self,
		tx: WaitingTrustedOperations<Hash, Ex>,
		shard: ShardIdentifier,
	) -> error::Result<Imported<Hash, Ex>> {
		let hash = tx.operation.hash.clone();
		let mut promoted = vec![];
		let mut failed = vec![];
		let mut removed = vec![];

		let mut first = true;
		let mut to_import = vec![tx];

		while let Some(tx) = to_import.pop() {
			// find operation in Future that it unlocks
			to_import.append(&mut self.future.satisfy_tags(&tx.operation.provides, shard));

			// import this operation
			let current_hash = tx.operation.hash.clone();
			match self.ready.import(tx, shard) {
				Ok(mut replaced) => {
					if !first {
						promoted.push(current_hash);
					}
					// The operations were removed from the ready pool. We might attempt to re-import them.
					removed.append(&mut replaced);
				},
				// operation failed to be imported.
				Err(e) =>
					if first {
						debug!(target: "txpool", "[{:?}] Error importing", current_hash,);
						return Err(e)
					} else {
						failed.push(current_hash);
					},
			}
			first = false;
		}

		// An edge case when importing operation caused
		// some future operations to be imported and that
		// future operations pushed out current operation.
		// This means that there is a cycle and the operations should
		// be moved back to future, since we can't resolve it.
		if removed.iter().any(|tx| tx.hash == hash) {
			// We still need to remove all operations that we promoted
			// since they depend on each other and will never get to the best iterator.
			self.ready.remove_subtree(&promoted, shard);

			debug!(target: "txpool", "[{:?}] Cycle detected, bailing.", hash);
			return Err(error::Error::CycleDetected)
		}

		Ok(Imported::Ready { hash, promoted, failed, removed })
	}

	/// Returns an iterator over ready operations in the pool.
	pub fn ready(
		&self,
		shard: ShardIdentifier,
	) -> impl Iterator<Item = Arc<TrustedOperation<Hash, Ex>>> {
		self.ready.get(shard)
	}

	/// Returns an iterator over all shards in the pool.
	pub fn get_shards(&self) -> impl Iterator<Item = &ShardIdentifier> {
		self.ready.get_shards()
	}

	/// Returns an iterator over future operations in the pool.
	pub fn futures(
		&self,
		shard: ShardIdentifier,
	) -> impl Iterator<Item = &TrustedOperation<Hash, Ex>> {
		self.future.all(shard)
	}

	/// Returns pool operations given list of hashes.
	///
	/// Includes both ready and future pool. For every hash in the `hashes`
	/// iterator an `Option` is produced (so the resulting `Vec` always have the same length).
	pub fn by_hashes(
		&self,
		hashes: &[Hash],
		shard: ShardIdentifier,
	) -> Vec<Option<Arc<TrustedOperation<Hash, Ex>>>> {
		let ready = self.ready.by_hashes(hashes, shard);
		let future = self.future.by_hashes(hashes, shard);

		ready.into_iter().zip(future).map(|(a, b)| a.or(b)).collect()
	}

	/// Returns pool operation by hash.
	pub fn ready_by_hash(
		&self,
		hash: &Hash,
		shard: ShardIdentifier,
	) -> Option<Arc<TrustedOperation<Hash, Ex>>> {
		self.ready.by_hash(hash, shard)
	}

	/// Makes sure that the operations in the queues stay within provided limits.
	///
	/// Removes and returns worst operations from the queues and all operations that depend on them.
	/// Technically the worst operation should be evaluated by computing the entire pending set.
	/// We use a simplified approach to remove the operation that occupies the pool for the longest time.
	pub fn enforce_limits(
		&mut self,
		ready: &Limit,
		future: &Limit,
		shard: ShardIdentifier,
	) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		let mut removed = vec![];

		while ready.is_exceeded(self.ready.len(shard), self.ready.bytes(shard)) {
			// find the worst operation
			let minimal = self.ready.fold(
				|minimal, current| {
					let operation = &current.operation;
					match minimal {
						None => Some(operation.clone()),
						Some(ref tx) if tx.insertion_id > operation.insertion_id =>
							Some(operation.clone()),
						other => other,
					}
				},
				shard,
			);

			if let Some(minimal) = minimal {
				removed.append(&mut self.remove_subtree(&[minimal.operation.hash.clone()], shard))
			} else {
				break
			}
		}

		while future.is_exceeded(self.future.len(shard), self.future.bytes(shard)) {
			// find the worst operation
			let minimal = self.future.fold(
				|minimal, current| {
					match minimal {
						None => Some(current.clone()),
						/*Some(ref tx) if tx.imported_at > current.imported_at => {
							Some(current.clone())
						},*/
						other => other,
					}
				},
				shard,
			);

			if let Some(minimal) = minimal {
				removed.append(&mut self.remove_subtree(&[minimal.operation.hash.clone()], shard))
			} else {
				break
			}
		}

		removed
	}

	/// Removes all operations represented by the hashes and all other operations
	/// that depend on them.
	///
	/// Returns a list of actually removed operations.
	/// NOTE some operations might still be valid, but were just removed because
	/// they were part of a chain, you may attempt to re-import them later.
	/// NOTE If you want to remove ready operations that were already used
	/// and you don't want them to be stored in the pool use `prune_tags` method.
	pub fn remove_subtree(
		&mut self,
		hashes: &[Hash],
		shard: ShardIdentifier,
	) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		let mut removed = self.ready.remove_subtree(hashes, shard);
		removed.extend(self.future.remove(hashes, shard));
		removed
	}

	/// Removes and returns all operations from the future queue.
	pub fn clear_future(&mut self, shard: ShardIdentifier) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		self.future.clear(shard)
	}

	/// Prunes operations that provide given list of tags.
	///
	/// This will cause all operations that provide these tags to be removed from the pool,
	/// but unlike `remove_subtree`, dependent operations are not touched.
	/// Additional operations from future queue might be promoted to ready if you satisfy tags
	/// that the pool didn't previously know about.
	pub fn prune_tags(
		&mut self,
		tags: impl IntoIterator<Item = Tag>,
		shard: ShardIdentifier,
	) -> PruneStatus<Hash, Ex> {
		let mut to_import = vec![];
		let mut pruned = vec![];
		let recently_pruned = &mut self.recently_pruned[self.recently_pruned_index];
		self.recently_pruned_index = (self.recently_pruned_index + 1) % RECENTLY_PRUNED_TAGS;
		recently_pruned.clear();

		for tag in tags {
			// make sure to promote any future operations that could be unlocked
			to_import.append(&mut self.future.satisfy_tags(iter::once(&tag), shard));
			// and actually prune operations in ready queue
			pruned.append(&mut self.ready.prune_tags(tag.clone(), shard));
			// store the tags for next submission
			recently_pruned.insert(tag);
		}

		let mut promoted = vec![];
		let mut failed = vec![];
		for tx in to_import {
			let hash = tx.operation.hash.clone();
			match self.import_to_ready(tx, shard) {
				Ok(res) => promoted.push(res),
				Err(_e) => {
					warn!(target: "txpool", "[{:?}] Failed to promote during pruning", hash);
					failed.push(hash)
				},
			}
		}

		PruneStatus { promoted, failed, pruned }
	}

	/// Get pool status.
	pub fn status(&self, shard: ShardIdentifier) -> PoolStatus {
		PoolStatus {
			ready: self.ready.len(shard),
			ready_bytes: self.ready.bytes(shard),
			future: self.future.len(shard),
			future_bytes: self.future.bytes(shard),
		}
	}
}

/// Queue limits
#[derive(Debug, Clone)]
pub struct Limit {
	/// Maximal number of operations in the queue.
	pub count: usize,
	/// Maximal size of encodings of all operations in the queue.
	pub total_bytes: usize,
}

impl Limit {
	/// Returns true if any of the provided values exceeds the limit.
	pub fn is_exceeded(&self, count: usize, bytes: usize) -> bool {
		self.count < count || self.total_bytes < bytes
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use alloc::borrow::ToOwned;

	type Hash = u64;

	fn test_pool() -> BasePool<Hash, Vec<u8>> {
		BasePool::default()
	}

	#[test]
	pub fn test_should_import_transaction_to_ready() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1u64,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		// then
		assert_eq!(pool.ready(shard).count(), 1);
		assert_eq!(pool.ready.len(shard), 1);
	}

	#[test]
	pub fn test_should_not_import_same_transaction_twice() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap_err();

		// then
		assert_eq!(pool.ready(shard).count(), 1);
		assert_eq!(pool.ready.len(shard), 1);
	}

	#[test]
	pub fn test_should_import_transaction_to_future_and_promote_it_later() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		assert_eq!(pool.ready(shard).count(), 0);
		assert_eq!(pool.ready.len(shard), 0);
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![0]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		// then
		assert_eq!(pool.ready(shard).count(), 2);
		assert_eq!(pool.ready.len(shard), 2);
	}

	#[test]
	pub fn test_should_promote_a_subgraph() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![3u8],
				bytes: 1,
				hash: 3,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![2]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![1]],
				provides: vec![vec![3], vec![2]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![4u8],
				bytes: 1,
				hash: 4,
				priority: 1_000u64,
				valid_till: 64u64,
				requires: vec![vec![3], vec![4]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		assert_eq!(pool.ready(shard).count(), 0);
		assert_eq!(pool.ready.len(shard), 0);

		let res = pool
			.import(
				TrustedOperation {
					data: vec![5u8],
					bytes: 1,
					hash: 5,
					priority: 5u64,
					valid_till: 64u64,
					requires: vec![],
					provides: vec![vec![0], vec![4]],
					propagate: true,
					source: Source::External,
				},
				shard,
			)
			.unwrap();

		// then
		let mut it = pool.ready(shard).into_iter().map(|tx| tx.data[0]);

		assert_eq!(it.next(), Some(5));
		assert_eq!(it.next(), Some(1));
		assert_eq!(it.next(), Some(2));
		assert_eq!(it.next(), Some(4));
		assert_eq!(it.next(), Some(3));
		assert_eq!(it.next(), None);
		assert_eq!(
			res,
			Imported::Ready {
				hash: 5,
				promoted: vec![1, 2, 3, 4],
				failed: vec![],
				removed: vec![]
			}
		);
	}

	#[test]
	pub fn test_should_handle_a_cycle() {
		// given
		let shard = ShardIdentifier::default();
		let mut pool = test_pool();
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![3u8],
				bytes: 1,
				hash: 3,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![1]],
				provides: vec![vec![2]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		assert_eq!(pool.ready(shard).count(), 0);
		assert_eq!(pool.ready.len(shard), 0);

		// when
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![2]],
				provides: vec![vec![0]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		// then
		{
			let mut it = pool.ready(shard).into_iter().map(|tx| tx.data[0]);
			assert_eq!(it.next(), None);
		}
		// all operations occupy the Future queue - it's fine
		assert_eq!(pool.future.len(shard), 3);

		// let's close the cycle with one additional operation
		let res = pool
			.import(
				TrustedOperation {
					data: vec![4u8],
					bytes: 1,
					hash: 4,
					priority: 50u64,
					valid_till: 64u64,
					requires: vec![],
					provides: vec![vec![0]],
					propagate: true,
					source: Source::External,
				},
				shard,
			)
			.unwrap();
		let mut it = pool.ready(shard).into_iter().map(|tx| tx.data[0]);
		assert_eq!(it.next(), Some(4));
		assert_eq!(it.next(), Some(1));
		assert_eq!(it.next(), Some(3));
		assert_eq!(it.next(), None);
		assert_eq!(
			res,
			Imported::Ready { hash: 4, promoted: vec![1, 3], failed: vec![2], removed: vec![] }
		);
		assert_eq!(pool.future.len(shard), 0);
	}

	#[test]
	pub fn test_should_handle_a_cycle_with_low_priority() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![3u8],
				bytes: 1,
				hash: 3,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![1]],
				provides: vec![vec![2]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		assert_eq!(pool.ready(shard).count(), 0);
		assert_eq!(pool.ready.len(shard), 0);

		// when
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![2]],
				provides: vec![vec![0]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		// then
		{
			let mut it = pool.ready(shard).into_iter().map(|tx| tx.data[0]);
			assert_eq!(it.next(), None);
		}
		// all operations occupy the Future queue - it's fine
		assert_eq!(pool.future.len(shard), 3);

		// let's close the cycle with one additional operation
		let err = pool
			.import(
				TrustedOperation {
					data: vec![4u8],
					bytes: 1,
					hash: 4,
					priority: 1u64, // lower priority than Tx(2)
					valid_till: 64u64,
					requires: vec![],
					provides: vec![vec![0]],
					propagate: true,
					source: Source::External,
				},
				shard,
			)
			.unwrap_err();
		let mut it = pool.ready(shard).into_iter().map(|tx| tx.data[0]);
		assert_eq!(it.next(), None);
		assert_eq!(pool.ready.len(shard), 0);
		assert_eq!(pool.future.len(shard), 0);
		if let error::Error::CycleDetected = err {
		} else {
			assert!(false, "Invalid error kind: {:?}", err);
		}
	}

	#[test]
	pub fn test_can_track_heap_size() {
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();
		pool.import(
			TrustedOperation {
				data: vec![5u8; 1024],
				bytes: 1,
				hash: 5,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![0], vec![4]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.expect("import 1 should be ok");
		pool.import(
			TrustedOperation {
				data: vec![3u8; 1024],
				bytes: 1,
				hash: 7,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![2], vec![7]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.expect("import 2 should be ok");

		//assert!(parity_util_mem::malloc_size(&pool) > 5000);
	}

	#[test]
	pub fn test_should_remove_invalid_transactions() {
		// given
		let shard = ShardIdentifier::default();
		let mut pool = test_pool();
		pool.import(
			TrustedOperation {
				data: vec![5u8],
				bytes: 1,
				hash: 5,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![0], vec![4]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![3u8],
				bytes: 1,
				hash: 3,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![2]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![1]],
				provides: vec![vec![3], vec![2]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![4u8],
				bytes: 1,
				hash: 4,
				priority: 1_000u64,
				valid_till: 64u64,
				requires: vec![vec![3], vec![4]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		// future
		pool.import(
			TrustedOperation {
				data: vec![6u8],
				bytes: 1,
				hash: 6,
				priority: 1_000u64,
				valid_till: 64u64,
				requires: vec![vec![11]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		assert_eq!(pool.ready(shard).count(), 5);
		assert_eq!(pool.future.len(shard), 1);

		// when
		pool.remove_subtree(&[6, 1], shard);

		// then
		assert_eq!(pool.ready(shard).count(), 1);
		assert_eq!(pool.future.len(shard), 0);
	}

	#[test]
	pub fn test_should_prune_ready_transactions() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();
		// future (waiting for 0)
		pool.import(
			TrustedOperation {
				data: vec![5u8],
				bytes: 1,
				hash: 5,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![vec![100]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		// ready
		pool.import(
			TrustedOperation {
				data: vec![1u8],
				bytes: 1,
				hash: 1,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![],
				provides: vec![vec![1]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![2u8],
				bytes: 1,
				hash: 2,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![2]],
				provides: vec![vec![3]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![3u8],
				bytes: 1,
				hash: 3,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![1]],
				provides: vec![vec![2]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();
		pool.import(
			TrustedOperation {
				data: vec![4u8],
				bytes: 1,
				hash: 4,
				priority: 1_000u64,
				valid_till: 64u64,
				requires: vec![vec![3], vec![2]],
				provides: vec![vec![4]],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		assert_eq!(pool.ready(shard).count(), 4);
		assert_eq!(pool.future.len(shard), 1);

		// when
		let result = pool.prune_tags(vec![vec![0], vec![2]], shard);

		// then
		assert_eq!(result.pruned.len(), 2);
		assert_eq!(result.failed.len(), 0);
		assert_eq!(
			result.promoted[0],
			Imported::Ready { hash: 5, promoted: vec![], failed: vec![], removed: vec![] }
		);
		assert_eq!(result.promoted.len(), 1);
		assert_eq!(pool.future.len(shard), 0);
		assert_eq!(pool.ready.len(shard), 3);
		assert_eq!(pool.ready(shard).count(), 3);
	}

	#[test]
	pub fn test_transaction_debug() {
		assert_eq!(
			format!(
				"{:?}",
				TrustedOperation {
					data: vec![4u8],
					bytes: 1,
					hash: 4,
					priority: 1_000u64,
					valid_till: 64u64,
					requires: vec![vec![3], vec![2]],
					provides: vec![vec![4]],
					propagate: true,
					source: Source::External,
				}
			),
			"TrustedOperation { \
hash: 4, priority: 1000, valid_till: 64, bytes: 1, propagate: true, \
source: External, requires: [03,02], provides: [04], data: [4]}"
				.to_owned()
		);
	}

	#[test]
	pub fn test_transaction_propagation() {
		assert!(TrustedOperation {
			data: vec![4u8],
			bytes: 1,
			hash: 4,
			priority: 1_000u64,
			valid_till: 64u64,
			requires: vec![vec![3], vec![2]],
			provides: vec![vec![4]],
			propagate: true,
			source: Source::External,
		}
		.is_propagable());

		assert!(!TrustedOperation {
			data: vec![4u8],
			bytes: 1,
			hash: 4,
			priority: 1_000u64,
			valid_till: 64u64,
			requires: vec![vec![3], vec![2]],
			provides: vec![vec![4]],
			propagate: false,
			source: Source::External,
		}
		.is_propagable());
	}

	#[test]
	pub fn test_should_reject_future_transactions() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.reject_future_operations = true;

		// then
		let err = pool.import(
			TrustedOperation {
				data: vec![5u8],
				bytes: 1,
				hash: 5,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		);

		if let Err(error::Error::RejectedFutureTrustedOperation) = err {
		} else {
			assert!(false, "Invalid error kind: {:?}", err);
		}
	}

	#[test]
	pub fn test_should_clear_future_queue() {
		// given
		let mut pool = test_pool();
		let shard = ShardIdentifier::default();

		// when
		pool.import(
			TrustedOperation {
				data: vec![5u8],
				bytes: 1,
				hash: 5,
				priority: 5u64,
				valid_till: 64u64,
				requires: vec![vec![0]],
				provides: vec![],
				propagate: true,
				source: Source::External,
			},
			shard,
		)
		.unwrap();

		// then
		assert_eq!(pool.future.len(shard), 1);

		// and then when
		assert_eq!(pool.clear_future(shard).len(), 1);

		// then
		assert_eq!(pool.future.len(shard), 0);
	}

	#[test]
	pub fn test_should_accept_future_transactions_when_explicitly_asked_to() {
		// given
		let mut pool = test_pool();
		pool.reject_future_operations = true;
		let shard = ShardIdentifier::default();

		// when
		let flag_value = pool.with_futures_enabled(|pool, flag| {
			pool.import(
				TrustedOperation {
					data: vec![5u8],
					bytes: 1,
					hash: 5,
					priority: 5u64,
					valid_till: 64u64,
					requires: vec![vec![0]],
					provides: vec![],
					propagate: true,
					source: Source::External,
				},
				shard,
			)
			.unwrap();

			flag
		});

		// then
		assert!(flag_value);
		assert!(pool.reject_future_operations);
		assert_eq!(pool.future.len(shard), 1);
	}
}
