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

pub extern crate alloc;
use crate::{
	base_pool::TrustedOperation,
	error,
	future::WaitingTrustedOperations,
	tracked_map::{self, ReadOnlyTrackedMap, TrackedMap},
};
use alloc::{boxed::Box, collections::BTreeSet, sync::Arc, vec, vec::Vec};
use core::{cmp, cmp::Ord, default::Default, hash};
use itp_stf_primitives::types::ShardIdentifier;
use log::trace;
use sp_runtime::{traits::Member, transaction_validity::TransactionTag as Tag};
use std::collections::{HashMap, HashSet};

type TopErrorResult<Hash, Ex> = error::Result<(Vec<Arc<TrustedOperation<Hash, Ex>>>, Vec<Hash>)>;

/// An in-pool operation reference.
///
/// Should be cheap to clone.
#[derive(Debug)]
pub struct OperationRef<Hash, Ex> {
	/// The actual operation data.
	pub operation: Arc<TrustedOperation<Hash, Ex>>,
	/// Unique id when operation was inserted into the pool.
	pub insertion_id: u64,
}

impl<Hash, Ex> Clone for OperationRef<Hash, Ex> {
	fn clone(&self) -> Self {
		OperationRef { operation: self.operation.clone(), insertion_id: self.insertion_id }
	}
}

impl<Hash, Ex> Ord for OperationRef<Hash, Ex> {
	fn cmp(&self, other: &Self) -> cmp::Ordering {
		self.operation
			.priority
			.cmp(&other.operation.priority)
			.then_with(|| other.operation.valid_till.cmp(&self.operation.valid_till))
			.then_with(|| other.insertion_id.cmp(&self.insertion_id))
	}
}

impl<Hash, Ex> PartialOrd for OperationRef<Hash, Ex> {
	fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl<Hash, Ex> PartialEq for OperationRef<Hash, Ex> {
	fn eq(&self, other: &Self) -> bool {
		self.cmp(other) == cmp::Ordering::Equal
	}
}
impl<Hash, Ex> Eq for OperationRef<Hash, Ex> {}

#[derive(Debug)]
pub struct ReadyTx<Hash, Ex> {
	/// A reference to a operation
	pub operation: OperationRef<Hash, Ex>,
	/// A list of operations that get unlocked by this one
	pub unlocks: Vec<Hash>,
	/// How many required tags are provided inherently
	///
	/// Some operations might be already pruned from the queue,
	/// so when we compute ready set we may consider this operations ready earlier.
	pub requires_offset: usize,
}

impl<Hash: Clone, Ex> Clone for ReadyTx<Hash, Ex> {
	fn clone(&self) -> Self {
		ReadyTx {
			operation: self.operation.clone(),
			unlocks: self.unlocks.clone(),
			requires_offset: self.requires_offset,
		}
	}
}

const HASH_READY: &str = r#"
Every time operation is imported its hash is placed in `ready` map and tags in `provided_tags`;
Every time operation is removed from the queue we remove the hash from `ready` map and from `provided_tags`;
Hence every hash retrieved from `provided_tags` is always present in `ready`;
qed
"#;

#[derive(Debug)]
pub struct ReadyOperations<Hash: hash::Hash + Eq + Ord, Ex> {
	/// Insertion id
	insertion_id: HashMap<ShardIdentifier, u64>,
	/// tags that are provided by Ready operations
	provided_tags: HashMap<ShardIdentifier, HashMap<Tag, Hash>>,
	/// Trusted Operations that are ready (i.e. don't have any requirements external to the pool)
	ready: HashMap<ShardIdentifier, TrackedMap<Hash, ReadyTx<Hash, Ex>>>,
	/// Best operations that are ready to be included to the block without any other previous operation.
	best: HashMap<ShardIdentifier, BTreeSet<OperationRef<Hash, Ex>>>,
}

impl<Hash, Ex> tracked_map::Size for ReadyTx<Hash, Ex> {
	fn size(&self) -> usize {
		self.operation.operation.bytes
	}
}

impl<Hash: hash::Hash + Eq + Ord, Ex> Default for ReadyOperations<Hash, Ex> {
	fn default() -> Self {
		ReadyOperations {
			insertion_id: Default::default(),
			provided_tags: Default::default(),
			ready: Default::default(),
			best: Default::default(),
		}
	}
}

impl<Hash: hash::Hash + Member + Ord, Ex> ReadyOperations<Hash, Ex> {
	/// Borrows a map of tags that are provided by operations in this queue.
	pub fn provided_tags(&self, shard: ShardIdentifier) -> Option<&HashMap<Tag, Hash>> {
		if let Some(tag_pool) = &self.provided_tags.get(&shard) {
			return Some(tag_pool)
		}
		None
	}

	/// Returns an iterator of ready operations.
	///
	/// Trusted Operations are returned in order:
	/// 1. First by the dependencies:
	///    - never return operation that requires a tag, which was not provided by one of the previously returned operations
	/// 2. Then by priority:
	///    - If there are two operations with all requirements satisfied the one with higher priority goes first.
	/// 3. Then by the ttl that's left
	///    - operations that are valid for a shorter time go first
	/// 4. Lastly we sort by the time in the queue
	///    - operations that are longer in the queue go first
	pub fn get(
		&self,
		shard: ShardIdentifier,
	) -> impl Iterator<Item = Arc<TrustedOperation<Hash, Ex>>> {
		// check if shard tx pool exists
		if let Some(ready_map) = self.ready.get(&shard) {
			return BestIterator {
				all: ready_map.get_read_only_clone(),
				best: self.best.get(&shard).unwrap().clone(),
				awaiting: Default::default(),
			}
		}
		let tracked_map: TrackedMap<Hash, ReadyTx<Hash, Ex>> = Default::default();
		BestIterator {
			all: tracked_map.get_read_only_clone(),
			best: Default::default(),
			awaiting: Default::default(),
		}
	}
	/// Returns an iterator over all shards
	pub fn get_shards(&self) -> Box<dyn Iterator<Item = &ShardIdentifier> + '_> {
		// check if shard tx pool exists
		Box::new(self.ready.keys())
	}

	/// Imports operations to the pool of ready operations.
	///
	/// The operation needs to have all tags satisfied (be ready) by operations
	/// that are in this queue.
	/// Returns operations that were replaced by the one imported.
	pub fn import(
		&mut self,
		tx: WaitingTrustedOperations<Hash, Ex>,
		shard: ShardIdentifier,
	) -> error::Result<Vec<Arc<TrustedOperation<Hash, Ex>>>> {
		assert!(
			tx.is_ready(),
			"Only ready operations can be imported. Missing: {:?}",
			tx.missing_tags
		);
		if let Some(ready_map) = &self.ready.get(&shard) {
			assert!(
				!ready_map.read().contains_key(&tx.operation.hash),
				"TrustedOperation is already imported."
			);
		}
		// Get shard pool or create if not yet existing
		let current_insertion_id = self.insertion_id.entry(shard).or_insert_with(|| {
			let x: u64 = Default::default();
			x
		});

		*current_insertion_id += 1;
		let insertion_id = *current_insertion_id;
		let hash = tx.operation.hash.clone();
		let operation = tx.operation;

		let (replaced, unlocks) = self.replace_previous(&operation, shard)?;

		let mut goes_to_best = true;
		let tracked_ready = self.ready.entry(shard).or_insert_with(|| {
			let x: TrackedMap<Hash, ReadyTx<Hash, Ex>> = Default::default();
			x
		});
		let mut ready = tracked_ready.write();
		let mut requires_offset = 0;
		// Add links to operations that unlock the current one
		let tag_map = self.provided_tags.entry(shard).or_insert_with(|| {
			let x: HashMap<Tag, Hash> = Default::default();
			x
		});
		for tag in &operation.requires {
			// Check if the operation that satisfies the tag is still in the queue.
			if let Some(other) = tag_map.get(tag) {
				let tx = ready.get_mut(other).expect(HASH_READY);
				tx.unlocks.push(hash.clone());
				// this operation depends on some other, so it doesn't go to best directly.
				goes_to_best = false;
			} else {
				requires_offset += 1;
			}
		}

		// update provided_tags
		// call to replace_previous guarantees that we will be overwriting
		// only entries that have been removed.

		for tag in &operation.provides {
			tag_map.insert(tag.clone(), hash.clone());
		}

		let operation = OperationRef { operation, insertion_id };

		// insert to best if it doesn't require any other operation to be included before it
		let best_set = self.best.entry(shard).or_insert_with(|| {
			let x: BTreeSet<OperationRef<Hash, Ex>> = Default::default();
			x
		});
		if goes_to_best {
			best_set.insert(operation.clone());
		}

		// insert to Ready
		ready.insert(hash, ReadyTx { operation, unlocks, requires_offset });

		Ok(replaced)
	}

	/// Fold a list of ready operations to compute a single value.
	pub fn fold<R, F: FnMut(Option<R>, &ReadyTx<Hash, Ex>) -> Option<R>>(
		&mut self,
		f: F,
		shard: ShardIdentifier,
	) -> Option<R> {
		if let Some(ready_map) = self.ready.get(&shard) {
			return ready_map.read().values().fold(None, f)
		}
		None
	}

	/// Returns true if given hash is part of the queue.
	pub fn contains(&self, hash: &Hash, shard: ShardIdentifier) -> bool {
		if let Some(ready_map) = self.ready.get(&shard) {
			return ready_map.read().contains_key(hash)
		}
		false
	}

	/// Retrive operation by hash
	pub fn by_hash(
		&self,
		hash: &Hash,
		shard: ShardIdentifier,
	) -> Option<Arc<TrustedOperation<Hash, Ex>>> {
		self.by_hashes(&[hash.clone()], shard).into_iter().next().unwrap_or(None)
	}

	/// Retrieve operations by hash
	pub fn by_hashes(
		&self,
		hashes: &[Hash],
		shard: ShardIdentifier,
	) -> Vec<Option<Arc<TrustedOperation<Hash, Ex>>>> {
		if let Some(ready_map) = self.ready.get(&shard) {
			let ready = ready_map.read();
			return hashes
				.iter()
				.map(|hash| ready.get(hash).map(|x| x.operation.operation.clone()))
				.collect()
		}
		vec![]
	}

	/// Removes a subtree of operations from the ready pool.
	///
	/// NOTE removing a operation will also cause a removal of all operations that depend on that one
	/// (i.e. the entire subgraph that this operation is a start of will be removed).
	/// All removed operations are returned.
	pub fn remove_subtree(
		&mut self,
		hashes: &[Hash],
		shard: ShardIdentifier,
	) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		let to_remove = hashes.to_vec();
		self.remove_subtree_with_tag_filter(to_remove, None, shard)
	}

	/// Removes a subtrees of operations trees starting from roots given in `to_remove`.
	///
	/// We proceed with a particular branch only if there is at least one provided tag
	/// that is not part of `provides_tag_filter`. I.e. the filter contains tags
	/// that will stay in the pool, so that we can early exit and avoid descending.
	fn remove_subtree_with_tag_filter(
		&mut self,
		mut to_remove: Vec<Hash>,
		provides_tag_filter: Option<HashSet<Tag>>,
		shard: ShardIdentifier,
	) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		let mut removed = vec![];
		if let Some(ready_map) = self.ready.get_mut(&shard) {
			let mut ready = ready_map.write();
			while let Some(hash) = to_remove.pop() {
				if let Some(mut tx) = ready.remove(&hash) {
					let invalidated = tx.operation.operation.provides.iter().filter(|tag| {
						provides_tag_filter
							.as_ref()
							.map(|filter| !filter.contains(&**tag))
							.unwrap_or(true)
					});

					let mut removed_some_tags = false;
					// remove entries from provided_tags
					for tag in invalidated {
						removed_some_tags = true;
						self.provided_tags.get_mut(&shard).unwrap().remove(tag);
					}

					// remove from unlocks
					for tag in &tx.operation.operation.requires {
						if let Some(hash) = self.provided_tags.get(&shard).unwrap().get(tag) {
							if let Some(tx) = ready.get_mut(hash) {
								remove_item(&mut tx.unlocks, hash);
							}
						}
					}

					// remove from best
					self.best.get_mut(&shard).unwrap().remove(&tx.operation);

					if removed_some_tags {
						// remove all operations that the current one unlocks
						to_remove.append(&mut tx.unlocks);
					}

					// add to removed
					trace!(target: "txpool", "[{:?}] Removed as part of the subtree.", hash);
					removed.push(tx.operation.operation);
				}
			}
		}

		removed
	}

	/// Removes operations that provide given tag.
	///
	/// All operations that lead to a operation, which provides this tag
	/// are going to be removed from the queue, but no other operations are touched -
	/// i.e. all other subgraphs starting from given tag are still considered valid & ready.
	pub fn prune_tags(
		&mut self,
		tag: Tag,
		shard: ShardIdentifier,
	) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
		let mut removed = vec![];
		let mut to_remove = vec![tag];

		if self.provided_tags.contains_key(&shard) {
			while let Some(tag) = to_remove.pop() {
				let res = self
					.provided_tags
					.get_mut(&shard)
					.unwrap()
					.remove(&tag)
					.and_then(|hash| self.ready.get_mut(&shard).unwrap().write().remove(&hash));

				if let Some(tx) = res {
					let unlocks = tx.unlocks;

					// Make sure we remove it from best txs
					self.best.get_mut(&shard).unwrap().remove(&tx.operation);

					let tx = tx.operation.operation;

					// prune previous operations as well
					{
						let hash = &tx.hash;
						let mut find_previous = |tag| -> Option<Vec<Tag>> {
							let prev_hash = self.provided_tags.get(&shard).unwrap().get(tag)?;
							let mut ready = self.ready.get_mut(&shard).unwrap().write();
							let tx2 = ready.get_mut(prev_hash)?;
							remove_item(&mut tx2.unlocks, hash);
							// We eagerly prune previous operations as well.
							// But it might not always be good.
							// Possible edge case:
							// - tx provides two tags
							// - the second tag enables some subgraph we don't know of yet
							// - we will prune the operation
							// - when we learn about the subgraph it will go to future
							// - we will have to wait for re-propagation of that operation
							// Alternatively the caller may attempt to re-import these operations.
							if tx2.unlocks.is_empty() {
								Some(tx2.operation.operation.provides.clone())
							} else {
								None
							}
						};

						// find previous operations
						for tag in &tx.requires {
							if let Some(mut tags_to_remove) = find_previous(tag) {
								to_remove.append(&mut tags_to_remove);
							}
						}
					}

					// add the operations that just got unlocked to `best`
					for hash in unlocks {
						if let Some(tx) = self.ready.get_mut(&shard).unwrap().write().get_mut(&hash)
						{
							tx.requires_offset += 1;
							// this operation is ready
							if tx.requires_offset == tx.operation.operation.requires.len() {
								self.best.get_mut(&shard).unwrap().insert(tx.operation.clone());
							}
						}
					}

					// we also need to remove all other tags that this operation provides,
					// but since all the hard work is done, we only clear the provided_tag -> hash
					// mapping.
					let current_tag = &tag;
					for tag in &tx.provides {
						let removed = self.provided_tags.get_mut(&shard).unwrap().remove(tag);
						assert_eq!(
							removed.as_ref(),
							if current_tag == tag { None } else { Some(&tx.hash) },
							"The pool contains exactly one operation providing given tag; the removed operation
							claims to provide that tag, so it has to be mapped to it's hash; qed"
						);
					}

					removed.push(tx);
				}
			}
		}

		removed
	}

	/// Checks if the operation is providing the same tags as other operations.
	///
	/// In case that's true it determines if the priority of operations that
	/// we are about to replace is lower than the priority of the replacement operation.
	/// We remove/replace old operations in case they have lower priority.
	///
	/// In case replacement is successful returns a list of removed operations
	/// and a list of hashes that are still in pool and gets unlocked by the new operation.
	fn replace_previous(
		&mut self,
		tx: &TrustedOperation<Hash, Ex>,
		shard: ShardIdentifier,
	) -> TopErrorResult<Hash, Ex> {
		if let Some(provided_tag_map) = self.provided_tags.get(&shard) {
			let (to_remove, unlocks) = {
				// check if we are replacing a operation
				let replace_hashes = tx
					.provides
					.iter()
					.filter_map(|tag| provided_tag_map.get(tag))
					.collect::<HashSet<_>>();

				// early exit if we are not replacing anything.
				if replace_hashes.is_empty() {
					return Ok((vec![], vec![]))
				}

				// now check if collective priority is lower than the replacement operation.
				let old_priority = {
					let ready = self.ready.get(&shard).unwrap().read();
					replace_hashes
						.iter()
						.filter_map(|hash| ready.get(hash))
						.fold(0u64, |total, tx| {
							total.saturating_add(tx.operation.operation.priority)
						})
				};

				// bail - the operation has too low priority to replace the old ones
				if old_priority >= tx.priority {
					return Err(error::Error::TooLowPriority(tx.priority))
				}

				// construct a list of unlocked operations
				let unlocks = {
					let ready = self.ready.get(&shard).unwrap().read();
					replace_hashes.iter().filter_map(|hash| ready.get(hash)).fold(
						vec![],
						|mut list, tx| {
							list.extend(tx.unlocks.iter().cloned());
							list
						},
					)
				};

				(replace_hashes.into_iter().cloned().collect::<Vec<_>>(), unlocks)
			};

			let new_provides = tx.provides.iter().cloned().collect::<HashSet<_>>();
			let removed = self.remove_subtree_with_tag_filter(to_remove, Some(new_provides), shard);

			return Ok((removed, unlocks))
		}
		Ok((vec![], vec![]))
	}

	/// Returns number of operations in this queue.
	#[allow(clippy::len_without_is_empty)]
	pub fn len(&self, shard: ShardIdentifier) -> usize {
		self.ready.get(&shard).map_or(0, |ready_map| ready_map.len())
	}

	/// Returns sum of encoding lengths of all operations in this queue.
	pub fn bytes(&self, shard: ShardIdentifier) -> usize {
		self.ready.get(&shard).map_or(0, |ready_map| ready_map.bytes())
	}
}

/// Iterator of ready operations ordered by priority.
pub struct BestIterator<Hash, Ex> {
	all: ReadOnlyTrackedMap<Hash, ReadyTx<Hash, Ex>>,
	awaiting: HashMap<Hash, (usize, OperationRef<Hash, Ex>)>,
	best: BTreeSet<OperationRef<Hash, Ex>>,
}

/*impl Default for BestIterator<Hash, Ex> {
	let insertion_id = 0;
	let operation = Arc::new(with_priority(3, 3))
	let tx_default = OperationRef {
		insertion_id,
		operation
	};
	fn default() ->  self.awaiting.insert("NA", (0, tx_default))
}*/

impl<Hash: hash::Hash + Member + Ord, Ex> BestIterator<Hash, Ex> {
	/// Depending on number of satisfied requirements insert given ref
	/// either to awaiting set or to best set.
	fn best_or_awaiting(&mut self, satisfied: usize, tx_ref: OperationRef<Hash, Ex>) {
		if satisfied >= tx_ref.operation.requires.len() {
			// If we have satisfied all deps insert to best
			self.best.insert(tx_ref);
		} else {
			// otherwise we're still awaiting for some deps
			self.awaiting.insert(tx_ref.operation.hash.clone(), (satisfied, tx_ref));
		}
	}
}

impl<Hash: hash::Hash + Member + Ord, Ex> Iterator for BestIterator<Hash, Ex> {
	type Item = Arc<TrustedOperation<Hash, Ex>>;

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			let best = self.best.iter().next_back()?.clone();
			let best = self.best.take(&best)?;

			let next = self.all.read().get(&best.operation.hash).cloned();
			let ready = match next {
				Some(ready) => ready,
				// The operation is not in all, maybe it was removed in the meantime?
				None => continue,
			};

			// Insert operations that just got unlocked.
			for hash in &ready.unlocks {
				// first check local awaiting operations
				let res = if let Some((mut satisfied, tx_ref)) = self.awaiting.remove(hash) {
					satisfied += 1;
					Some((satisfied, tx_ref))
				// then get from the pool
				} else {
					self.all
						.read()
						.get(hash)
						.map(|next| (next.requires_offset + 1, next.operation.clone()))
				};

				if let Some((satisfied, tx_ref)) = res {
					self.best_or_awaiting(satisfied, tx_ref)
				}
			}

			return Some(best.operation)
		}
	}
}

// See: https://github.com/rust-lang/rust/issues/40062
fn remove_item<T: PartialEq>(vec: &mut Vec<T>, item: &T) {
	if let Some(idx) = vec.iter().position(|i| i == item) {
		vec.swap_remove(idx);
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use crate::primitives::TrustedOperationSource as Source;

	fn tx(id: u8) -> TrustedOperation<u64, Vec<u8>> {
		TrustedOperation {
			data: vec![id],
			bytes: 1,
			hash: id as u64,
			priority: 1,
			valid_till: 2,
			requires: vec![vec![1], vec![2]],
			provides: vec![vec![3], vec![4]],
			propagate: true,
			source: Source::External,
		}
	}

	fn import<H: hash::Hash + Eq + Member + Ord, Ex>(
		ready: &mut ReadyOperations<H, Ex>,
		tx: TrustedOperation<H, Ex>,
		shard: ShardIdentifier,
	) -> error::Result<Vec<Arc<TrustedOperation<H, Ex>>>> {
		let x = WaitingTrustedOperations::new(tx, ready.provided_tags(shard), &[]);
		ready.import(x, shard)
	}

	#[test]
	pub fn test_should_replace_transaction_that_provides_the_same_tag() {
		// given
		let shard = ShardIdentifier::default();
		let mut ready = ReadyOperations::default();
		let mut tx1 = tx(1);
		tx1.requires.clear();
		let mut tx2 = tx(2);
		tx2.requires.clear();
		tx2.provides = vec![vec![3]];
		let mut tx3 = tx(3);
		tx3.requires.clear();
		tx3.provides = vec![vec![4]];

		// when
		import(&mut ready, tx2, shard).unwrap();
		import(&mut ready, tx3, shard).unwrap();
		assert_eq!(ready.get(shard).count(), 2);

		// too low priority
		import(&mut ready, tx1.clone(), shard).unwrap_err();

		tx1.priority = 10;
		import(&mut ready, tx1, shard).unwrap();

		// then
		assert_eq!(ready.get(shard).count(), 1);
	}

	#[test]
	pub fn test_should_replace_multiple_transactions_correctly() {
		// given
		let shard = ShardIdentifier::default();
		let mut ready = ReadyOperations::default();
		let mut tx0 = tx(0);
		tx0.requires = vec![];
		tx0.provides = vec![vec![0]];
		let mut tx1 = tx(1);
		tx1.requires = vec![];
		tx1.provides = vec![vec![1]];
		let mut tx2 = tx(2);
		tx2.requires = vec![vec![0], vec![1]];
		tx2.provides = vec![vec![2], vec![3]];
		let mut tx3 = tx(3);
		tx3.requires = vec![vec![2]];
		tx3.provides = vec![vec![4]];
		let mut tx4 = tx(4);
		tx4.requires = vec![vec![3]];
		tx4.provides = vec![vec![5]];
		// replacement
		let mut tx2_2 = tx(5);
		tx2_2.requires = vec![vec![0], vec![1]];
		tx2_2.provides = vec![vec![2]];
		tx2_2.priority = 10;

		for tx in vec![tx0, tx1, tx2, tx3, tx4] {
			import(&mut ready, tx, shard).unwrap();
		}
		assert_eq!(ready.get(shard).count(), 5);

		// when
		import(&mut ready, tx2_2, shard).unwrap();

		// then
		assert_eq!(ready.get(shard).count(), 3);
	}

	#[test]
	pub fn test_should_return_best_transactions_in_correct_order() {
		// given
		let shard = ShardIdentifier::default();
		let mut ready = ReadyOperations::default();
		let mut tx1 = tx(1);
		tx1.requires.clear();
		let mut tx2 = tx(2);
		tx2.requires = tx1.provides.clone();
		tx2.provides = vec![vec![106]];
		let mut tx3 = tx(3);
		tx3.requires = vec![tx1.provides[0].clone(), vec![106]];
		tx3.provides = vec![];
		let mut tx4 = tx(4);
		tx4.requires = vec![tx1.provides[0].clone()];
		tx4.provides = vec![];
		let tx5 = TrustedOperation {
			data: vec![5],
			bytes: 1,
			hash: 5,
			priority: 1,
			valid_till: u64::max_value(), // use the max_value() here for testing.
			requires: vec![tx1.provides[0].clone()],
			provides: vec![],
			propagate: true,
			source: Source::External,
		};

		// when
		for tx in vec![tx1, tx2, tx3, tx4, tx5] {
			import(&mut ready, tx, shard).unwrap();
		}

		// then
		assert_eq!(ready.best.len(), 1);

		let mut it = ready.get(shard).map(|tx| tx.data[0]);

		assert_eq!(it.next(), Some(1));
		assert_eq!(it.next(), Some(2));
		assert_eq!(it.next(), Some(3));
		assert_eq!(it.next(), Some(4));
		assert_eq!(it.next(), Some(5));
		assert_eq!(it.next(), None);
	}

	#[test]
	pub fn test_should_order_refs() {
		let mut id = 1;
		let mut with_priority = |priority, longevity| {
			id += 1;
			let mut tx = tx(id);
			tx.priority = priority;
			tx.valid_till = longevity;
			tx
		};
		// higher priority = better
		assert!(
			OperationRef { operation: Arc::new(with_priority(3, 3)), insertion_id: 1 }
				> OperationRef { operation: Arc::new(with_priority(2, 3)), insertion_id: 2 }
		);
		// lower validity = better
		assert!(
			OperationRef { operation: Arc::new(with_priority(3, 2)), insertion_id: 1 }
				> OperationRef { operation: Arc::new(with_priority(3, 3)), insertion_id: 2 }
		);
		// lower insertion_id = better
		assert!(
			OperationRef { operation: Arc::new(with_priority(3, 3)), insertion_id: 1 }
				> OperationRef { operation: Arc::new(with_priority(3, 3)), insertion_id: 2 }
		);
	}
}
