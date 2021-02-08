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

use alloc::{boxed::Box, fmt, sync::Arc, vec::Vec};
use core::hash;

use sgx_tstd::collections::{HashMap, HashSet};

use sp_core::hexdisplay::HexDisplay;
use sp_runtime::transaction_validity::TransactionTag as Tag;

use sgx_tstd::{time::Instant, untrusted::time::InstantEx};

use substratee_stf::ShardIdentifier;

use crate::top_pool::base_pool::TrustedOperation;

/// TrustedOperation with partially satisfied dependencies.
pub struct WaitingTransaction<Hash, Ex> {
    /// TrustedOperation details.
    pub transaction: Arc<TrustedOperation<Hash, Ex>>,
    /// Tags that are required and have not been satisfied yet by other transactions in the pool.
    pub missing_tags: HashSet<Tag>,
    /// Time of import to the Future Queue.
    pub imported_at: Instant,
}

impl<Hash: fmt::Debug, Ex: fmt::Debug> fmt::Debug for WaitingTransaction<Hash, Ex> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "WaitingTransaction {{ ")?;
        //write!(fmt, "imported_at: {:?}, ", self.imported_at)?;
        write!(fmt, "transaction: {:?}, ", self.transaction)?;
        write!(fmt, "missing_tags: {{")?;
        let mut it = self.missing_tags.iter().map(|tag| HexDisplay::from(tag));
        if let Some(tag) = it.next() {
            write!(fmt, "{}", tag)?;
        }
        for tag in it {
            write!(fmt, ", {}", tag)?;
        }
        write!(fmt, " }}}}")
    }
}

impl<Hash, Ex> Clone for WaitingTransaction<Hash, Ex> {
    fn clone(&self) -> Self {
        WaitingTransaction {
            transaction: self.transaction.clone(),
            missing_tags: self.missing_tags.clone(),
            imported_at: self.imported_at.clone(),
        }
    }
}

impl<Hash, Ex> WaitingTransaction<Hash, Ex> {
    /// Creates a new `WaitingTransaction`.
    ///
    /// Computes the set of missing tags based on the requirements and tags that
    /// are provided by all transactions in the ready queue.
    pub fn new(
        transaction: TrustedOperation<Hash, Ex>,
        provided: Option<&HashMap<Tag, Hash>>,
        recently_pruned: &[HashSet<Tag>],
    ) -> Self {
        let missing_tags = transaction
            .requires
            .iter()
            .filter(|tag| {
                // is true if the tag is already satisfied either via transaction in the pool
                // or one that was recently included.

                let is_provided = recently_pruned.iter().any(|x| x.contains(&**tag))
                    || match provided {
                        Some(tags) => tags.contains_key(&**tag),
                        None => false,
                    };

                !is_provided
            })
            .cloned()
            .collect();

        WaitingTransaction {
            transaction: Arc::new(transaction),
            missing_tags,
            imported_at: Instant::now(),
        }
    }

    /// Marks the tag as satisfied.
    pub fn satisfy_tag(&mut self, tag: &Tag) {
        self.missing_tags.remove(tag);
    }

    /// Returns true if transaction has all requirements satisfied.
    pub fn is_ready(&self) -> bool {
        self.missing_tags.is_empty()
    }
}

/// A pool of transactions that are not yet ready to be included in the block.
///
/// Contains transactions that are still awaiting for some other transactions that
/// could provide a tag that they require.
#[derive(Debug)]
pub struct FutureTrustedOperations<Hash: hash::Hash + Eq, Ex> {
    /// tags that are not yet provided by any transaction and we await for them
    wanted_tags: HashMap<ShardIdentifier, HashMap<Tag, HashSet<Hash>>>,
    /// Transactions waiting for a particular other transaction
    waiting: HashMap<ShardIdentifier, HashMap<Hash, WaitingTransaction<Hash, Ex>>>,
}

impl<Hash: hash::Hash + Eq, Ex> Default for FutureTrustedOperations<Hash, Ex> {
    fn default() -> Self {
        FutureTrustedOperations {
            wanted_tags: Default::default(),
            waiting: Default::default(),
        }
    }
}

const WAITING_PROOF: &str = r"#
In import we always insert to `waiting` if we push to `wanted_tags`;
when removing from `waiting` we always clear `wanted_tags`;
every hash from `wanted_tags` is always present in `waiting`;
qed
#";

impl<Hash: hash::Hash + Eq + Clone, Ex> FutureTrustedOperations<Hash, Ex> {
    /// Import transaction to Future queue.
    ///
    /// Only transactions that don't have all their tags satisfied should occupy
    /// the Future queue.
    /// As soon as required tags are provided by some other transactions that are ready
    /// we should remove the transactions from here and move them to the Ready queue.
    pub fn import(&mut self, tx: WaitingTransaction<Hash, Ex>, shard: ShardIdentifier) {
        assert!(!tx.is_ready(), "TrustedOperation is ready.");
        if let Some(tx_pool_waiting) = self.waiting.get(&shard) {
            assert!(
                !tx_pool_waiting.contains_key(&tx.transaction.hash),
                "TrustedOperation is already imported."
            );
        }

        let tx_pool_waiting_map = self
            .waiting
            .entry(shard.clone())
            .or_insert_with(HashMap::new);
        let tx_pool_wanted_map = self
            .wanted_tags
            .entry(shard.clone())
            .or_insert_with(HashMap::new);
        // Add all tags that are missing
        for tag in &tx.missing_tags {
            let entry = tx_pool_wanted_map
                .entry(tag.clone())
                .or_insert_with(HashSet::new);
            entry.insert(tx.transaction.hash.clone());
        }

        // Add the transaction to a by-hash waiting map
        tx_pool_waiting_map.insert(tx.transaction.hash.clone(), tx);
    }

    /// Returns true if given hash is part of the queue.
    pub fn contains(&self, hash: &Hash, shard: ShardIdentifier) -> bool {
        if let Some(tx_pool_waiting) = self.waiting.get(&shard) {
            return tx_pool_waiting.contains_key(hash);
        }
        return false;
    }

    /// Returns a list of known transactions
    pub fn by_hashes(
        &self,
        hashes: &[Hash],
        shard: ShardIdentifier,
    ) -> Vec<Option<Arc<TrustedOperation<Hash, Ex>>>> {
        if let Some(tx_pool_waiting) = self.waiting.get(&shard) {
            return hashes
                .iter()
                .map(|h| tx_pool_waiting.get(h).map(|x| x.transaction.clone()))
                .collect();
        }
        return vec![];
    }

    /// Satisfies provided tags in transactions that are waiting for them.
    ///
    /// Returns (and removes) transactions that became ready after their last tag got
    /// satisfied and now we can remove them from Future and move to Ready queue.
    pub fn satisfy_tags<T: AsRef<Tag>>(
        &mut self,
        tags: impl IntoIterator<Item = T>,
        shard: ShardIdentifier,
    ) -> Vec<WaitingTransaction<Hash, Ex>> {
        let mut became_ready = vec![];

        for tag in tags {
            if let Some(tx_pool_wanted) = self.wanted_tags.get_mut(&shard) {
                if let Some(hashes) = tx_pool_wanted.remove(tag.as_ref()) {
                    if let Some(tx_pool_waiting) = self.waiting.get_mut(&shard) {
                        for hash in hashes {
                            let is_ready = {
                                let tx = tx_pool_waiting.get_mut(&hash).expect(WAITING_PROOF);
                                tx.satisfy_tag(tag.as_ref());
                                tx.is_ready()
                            };

                            if is_ready {
                                let tx = tx_pool_waiting.remove(&hash).expect(WAITING_PROOF);
                                became_ready.push(tx);
                            }
                        }
                    }
                }
            }
        }

        became_ready
    }

    /// Removes transactions for given list of hashes.
    ///
    /// Returns a list of actually removed transactions.
    pub fn remove(
        &mut self,
        hashes: &[Hash],
        shard: ShardIdentifier,
    ) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
        let mut removed = vec![];
        if let Some(tx_pool_waiting) = self.waiting.get_mut(&shard) {
            if let Some(tx_pool_wanted) = self.wanted_tags.get_mut(&shard) {
                for hash in hashes {
                    if let Some(waiting_tx) = tx_pool_waiting.remove(hash) {
                        // remove from wanted_tags as well
                        for tag in waiting_tx.missing_tags {
                            let remove = if let Some(wanted) = tx_pool_wanted.get_mut(&tag) {
                                wanted.remove(hash);
                                wanted.is_empty()
                            } else {
                                false
                            };
                            if remove {
                                tx_pool_wanted.remove(&tag);
                            }
                        }
                        // add to result
                        removed.push(waiting_tx.transaction)
                    }
                }
            }
        }
        removed
    }

    /// Fold a list of future transactions to compute a single value.
    pub fn fold<R, F: FnMut(Option<R>, &WaitingTransaction<Hash, Ex>) -> Option<R>>(
        &mut self,
        f: F,
        shard: ShardIdentifier,
    ) -> Option<R> {
        if let Some(tx_pool) = self.waiting.get(&shard) {
            return tx_pool.values().fold(None, f);
        }
        return None;
    }

    /// Returns iterator over all future transactions
    pub fn all(
        &self,
        shard: ShardIdentifier,
    ) -> Box<dyn Iterator<Item = &TrustedOperation<Hash, Ex>> + '_> {
        if let Some(tx_pool) = self.waiting.get(&shard) {
            return Box::new(tx_pool.values().map(|waiting| &*waiting.transaction));
        }
        return Box::new(core::iter::empty());
    }

    /// Removes and returns all future transactions.
    pub fn clear(&mut self, shard: ShardIdentifier) -> Vec<Arc<TrustedOperation<Hash, Ex>>> {
        if let Some(wanted_tx_pool) = self.wanted_tags.get_mut(&shard) {
            wanted_tx_pool.clear();
            return self
                .waiting
                .get_mut(&shard)
                .unwrap()
                .drain()
                .map(|(_, tx)| tx.transaction)
                .collect();
        }
        return vec![];
    }

    /// Returns number of transactions in the Future queue.
    pub fn len(&self, shard: ShardIdentifier) -> usize {
        if let Some(tx_pool) = self.waiting.get(&shard) {
            return tx_pool.len();
        }
        return 0;
    }

    /// Returns sum of encoding lengths of all transactions in this queue.
    pub fn bytes(&self, shard: ShardIdentifier) -> usize {
        if let Some(tx_pool) = self.waiting.get(&shard) {
            return tx_pool
                .values()
                .fold(0, |acc, tx| acc + tx.transaction.bytes);
        }
        return 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_runtime::transaction_validity::TransactionSource;

    #[test]
    fn can_track_heap_size() {
        let mut future = FutureTrustedOperations::default();
        future.import(WaitingTransaction {
            transaction: TrustedOperation {
                data: vec![0u8; 1024],
                bytes: 1,
                hash: 1,
                priority: 1,
                valid_till: 2,
                requires: vec![vec![1], vec![2]],
                provides: vec![vec![3], vec![4]],
                propagate: true,
                source: TransactionSource::External,
            }
            .into(),
            missing_tags: vec![vec![1u8], vec![2u8]].into_iter().collect(),
            //imported_at: std::time::Instant::now(),
        });

        // data is at least 1024!
        assert!(parity_util_mem::malloc_size(&future) > 1024);
    }
}
