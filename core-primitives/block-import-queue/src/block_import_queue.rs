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

//! Block import queue implementation

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::{Error, Result},
	PeekBlockQueue, PopFromBlockQueue, PushToBlockQueue,
};
use std::{collections::VecDeque, vec::Vec};

/// Block import queue.
///
/// Uses RwLock internally to guard against concurrent access and ensure all operations are atomic.
pub struct BlockImportQueue<SignedBlock> {
	queue: RwLock<VecDeque<SignedBlock>>,
}

impl<SignedBlock> BlockImportQueue<SignedBlock> {
	pub fn is_empty(&self) -> Result<bool> {
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.is_empty())
	}
}

impl<SignedBlock> Default for BlockImportQueue<SignedBlock> {
	fn default() -> Self {
		BlockImportQueue { queue: Default::default() }
	}
}

impl<SignedBlock> PushToBlockQueue<SignedBlock> for BlockImportQueue<SignedBlock> {
	fn push_multiple(&self, blocks: Vec<SignedBlock>) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.extend(blocks);
		Ok(())
	}

	fn push_single(&self, block: SignedBlock) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.push_back(block);
		Ok(())
	}
}

impl<SignedBlock> PopFromBlockQueue for BlockImportQueue<SignedBlock> {
	type BlockType = SignedBlock;

	fn pop_all_but_last(&self) -> Result<Vec<SignedBlock>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		let queue_length = queue_lock.len();
		if queue_length < 2 {
			return Ok(Vec::<SignedBlock>::default())
		}
		Ok(queue_lock.drain(..queue_length - 1).collect::<Vec<_>>())
	}

	fn pop_all(&self) -> Result<Vec<SignedBlock>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.drain(..).collect::<Vec<_>>())
	}

	fn pop_until<Predicate>(&self, predicate: Predicate) -> Result<Vec<Self::BlockType>>
	where
		Predicate: FnMut(&Self::BlockType) -> bool,
	{
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		match queue_lock.iter().position(predicate) {
			None => Ok(Vec::new()),
			Some(p) => Ok(queue_lock.drain(..p + 1).collect::<Vec<_>>()),
		}
	}

	fn pop_front(&self) -> Result<Option<Self::BlockType>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.pop_front())
	}
}

impl<SignedBlock> PeekBlockQueue for BlockImportQueue<SignedBlock>
where
	SignedBlock: Clone,
{
	type BlockType = SignedBlock;

	fn peek_find<Predicate>(&self, predicate: Predicate) -> Result<Option<Self::BlockType>>
	where
		Predicate: Fn(&Self::BlockType) -> bool,
	{
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		let maybe_block = queue_lock.iter().find(|&b| predicate(b));
		Ok(maybe_block.cloned())
	}

	fn peek_last(&self) -> Result<Option<Self::BlockType>> {
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.back().cloned())
	}

	fn peek_queue_size(&self) -> Result<usize> {
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.len())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;

	type TestBlock = u32;

	#[test]
	fn default_queue_is_empty() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert!(queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_on_default_returns_empty_vec() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert!(queue.pop_all().unwrap().is_empty());
	}

	#[test]
	fn after_inserting_queue_is_not_empty() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_single(TestBlock::default()).unwrap();
		assert!(!queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_after_inserting_leaves_empty_queue() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue
			.push_multiple(vec![TestBlock::default(), TestBlock::default(), TestBlock::default()])
			.unwrap();

		let all_popped = queue.pop_all().unwrap();
		assert_eq!(3, all_popped.len());
		assert!(queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_except_last_on_default_returns_empty_vec() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert!(queue.pop_all_but_last().unwrap().is_empty());
	}

	#[test]
	fn pop_all_except_last_with_single_element_returns_empty_vec() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_single(TestBlock::default()).unwrap();
		assert!(queue.pop_all_but_last().unwrap().is_empty());
	}

	#[test]
	fn pop_all_except_last_with_multiple_elements_returns_all_but_last_inserted() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 3, 5, 7]).unwrap();
		assert_eq!(3, queue.pop_all_but_last().unwrap().len());
		assert!(!queue.is_empty().unwrap());
		assert_eq!(7, queue.pop_all().unwrap()[0]);
	}

	#[test]
	fn pop_until_returns_empty_vec_if_nothing_matches() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 3, 5, 7]).unwrap();

		let popped_elements = queue.pop_until(|i| i > &10u32).unwrap();
		assert!(popped_elements.is_empty());
	}

	#[test]
	fn pop_until_returns_elements_until_and_including_match() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 10]).unwrap();

		assert_eq!(queue.pop_until(|i| i == &3).unwrap(), vec![1, 2, 3]);
	}

	#[test]
	fn pop_until_returns_all_elements_if_last_matches() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 10]).unwrap();

		assert_eq!(queue.pop_until(|i| i == &10).unwrap(), vec![1, 2, 3, 10]);
	}

	#[test]
	fn pop_until_returns_first_element_if_it_matches() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_single(4).unwrap();
		assert_eq!(queue.pop_until(|i| i == &4).unwrap(), vec![4])
	}

	#[test]
	fn pop_front_returns_none_if_queue_is_empty() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert_matches!(queue.pop_front().unwrap(), None);
	}

	#[test]
	fn pop_front_works() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5]).unwrap();
		assert_eq!(queue.pop_front().unwrap(), Some(1));
		assert_eq!(queue.pop_front().unwrap(), Some(2));
		assert_eq!(queue.pop_front().unwrap(), Some(3));
		assert_eq!(queue.pop_front().unwrap(), Some(5));
		assert_eq!(queue.pop_front().unwrap(), None);
	}

	#[test]
	fn peek_find_works() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5]).unwrap();

		assert_eq!(None, queue.peek_find(|i| i == &4).unwrap());
		assert!(queue.peek_find(|i| i == &1).unwrap().is_some());
		assert!(queue.peek_find(|i| i == &5).unwrap().is_some());
	}

	#[test]
	fn peek_find_on_empty_queue_returns_none() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert_eq!(None, queue.peek_find(|i| i == &1).unwrap());
	}

	#[test]
	fn peek_last_works() {
		let queue = BlockImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5, 6, 9, 10]).unwrap();
		assert_eq!(queue.peek_last().unwrap(), Some(10));
	}

	#[test]
	fn peek_last_on_empty_queue_returns_none() {
		let queue = BlockImportQueue::<TestBlock>::default();
		assert_eq!(None, queue.peek_last().unwrap());
	}
}
