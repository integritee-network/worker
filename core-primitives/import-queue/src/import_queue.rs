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

//! Import queue implementation

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::{Error, Result},
	PeekQueue, PopFromQueue, PushToQueue,
};
use std::{collections::VecDeque, vec::Vec};

/// Any import queue.
///
/// Uses RwLock internally to guard against concurrent access and ensure all operations are atomic.
pub struct ImportQueue<Item> {
	queue: RwLock<VecDeque<Item>>,
}

impl<Item> ImportQueue<Item> {
	pub fn is_empty(&self) -> Result<bool> {
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.is_empty())
	}
}

impl<Item> Default for ImportQueue<Item> {
	fn default() -> Self {
		ImportQueue { queue: Default::default() }
	}
}

impl<Item> PushToQueue<Item> for ImportQueue<Item> {
	fn push_multiple(&self, items: Vec<Item>) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.extend(items);
		Ok(())
	}

	fn push_single(&self, item: Item) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.push_back(item);
		Ok(())
	}
}

impl<Item> PopFromQueue for ImportQueue<Item> {
	type ItemType = Item;

	fn pop_all_but_last(&self) -> Result<Vec<Item>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		let queue_length = queue_lock.len();
		if queue_length < 2 {
			return Ok(Vec::<Item>::default())
		}
		Ok(queue_lock.drain(..queue_length - 1).collect::<Vec<_>>())
	}

	fn pop_all(&self) -> Result<Vec<Item>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.drain(..).collect::<Vec<_>>())
	}

	fn pop_until<Predicate>(&self, predicate: Predicate) -> Result<Vec<Self::ItemType>>
	where
		Predicate: FnMut(&Self::ItemType) -> bool,
	{
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		match queue_lock.iter().position(predicate) {
			None => Ok(Vec::new()),
			Some(p) => Ok(queue_lock.drain(..p + 1).collect::<Vec<_>>()),
		}
	}

	fn pop_front(&self) -> Result<Option<Self::ItemType>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.pop_front())
	}

	fn pop_from_front_until(&self, amount: usize) -> Result<Vec<Self::ItemType>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		if amount > queue_lock.len() {
			return Err(Error::Other(
				"Cannot Pop more items from the queue than are available".into(),
			))
		}
		Ok(queue_lock.drain(..amount).collect::<Vec<_>>())
	}
}

impl<Item> PeekQueue for ImportQueue<Item>
where
	Item: Clone,
{
	type ItemType = Item;

	fn peek_find<Predicate>(&self, predicate: Predicate) -> Result<Option<Self::ItemType>>
	where
		Predicate: Fn(&Self::ItemType) -> bool,
	{
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		let maybe_item = queue_lock.iter().find(|&b| predicate(b));
		Ok(maybe_item.cloned())
	}

	fn peek_last(&self) -> Result<Option<Self::ItemType>> {
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
		let queue = ImportQueue::<TestBlock>::default();
		assert!(queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_on_default_returns_empty_vec() {
		let queue = ImportQueue::<TestBlock>::default();
		assert!(queue.pop_all().unwrap().is_empty());
	}

	#[test]
	fn after_inserting_queue_is_not_empty() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_single(TestBlock::default()).unwrap();
		assert!(!queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_after_inserting_leaves_empty_queue() {
		let queue = ImportQueue::<TestBlock>::default();
		queue
			.push_multiple(vec![TestBlock::default(), TestBlock::default(), TestBlock::default()])
			.unwrap();

		let all_popped = queue.pop_all().unwrap();
		assert_eq!(3, all_popped.len());
		assert!(queue.is_empty().unwrap());
	}

	#[test]
	fn pop_all_except_last_on_default_returns_empty_vec() {
		let queue = ImportQueue::<TestBlock>::default();
		assert!(queue.pop_all_but_last().unwrap().is_empty());
	}

	#[test]
	fn pop_all_except_last_with_single_element_returns_empty_vec() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_single(TestBlock::default()).unwrap();
		assert!(queue.pop_all_but_last().unwrap().is_empty());
	}

	#[test]
	fn pop_all_except_last_with_multiple_elements_returns_all_but_last_inserted() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 3, 5, 7]).unwrap();
		assert_eq!(3, queue.pop_all_but_last().unwrap().len());
		assert!(!queue.is_empty().unwrap());
		assert_eq!(7, queue.pop_all().unwrap()[0]);
	}

	#[test]
	fn pop_until_returns_empty_vec_if_nothing_matches() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 3, 5, 7]).unwrap();

		let popped_elements = queue.pop_until(|i| i > &10u32).unwrap();
		assert!(popped_elements.is_empty());
	}

	#[test]
	fn pop_until_returns_elements_until_and_including_match() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 10]).unwrap();

		assert_eq!(queue.pop_until(|i| i == &3).unwrap(), vec![1, 2, 3]);
	}

	#[test]
	fn pop_until_returns_all_elements_if_last_matches() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 10]).unwrap();

		assert_eq!(queue.pop_until(|i| i == &10).unwrap(), vec![1, 2, 3, 10]);
	}

	#[test]
	fn pop_until_returns_first_element_if_it_matches() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_single(4).unwrap();
		assert_eq!(queue.pop_until(|i| i == &4).unwrap(), vec![4])
	}

	#[test]
	fn pop_front_returns_none_if_queue_is_empty() {
		let queue = ImportQueue::<TestBlock>::default();
		assert_matches!(queue.pop_front().unwrap(), None);
	}

	#[test]
	fn pop_front_works() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5]).unwrap();
		assert_eq!(queue.pop_front().unwrap(), Some(1));
		assert_eq!(queue.pop_front().unwrap(), Some(2));
		assert_eq!(queue.pop_front().unwrap(), Some(3));
		assert_eq!(queue.pop_front().unwrap(), Some(5));
		assert_eq!(queue.pop_front().unwrap(), None);
	}

	#[test]
	fn peek_find_works() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5]).unwrap();

		assert_eq!(None, queue.peek_find(|i| i == &4).unwrap());
		assert!(queue.peek_find(|i| i == &1).unwrap().is_some());
		assert!(queue.peek_find(|i| i == &5).unwrap().is_some());
	}

	#[test]
	fn peek_find_on_empty_queue_returns_none() {
		let queue = ImportQueue::<TestBlock>::default();
		assert_eq!(None, queue.peek_find(|i| i == &1).unwrap());
	}

	#[test]
	fn peek_last_works() {
		let queue = ImportQueue::<TestBlock>::default();
		queue.push_multiple(vec![1, 2, 3, 5, 6, 9, 10]).unwrap();
		assert_eq!(queue.peek_last().unwrap(), Some(10));
	}

	#[test]
	fn peek_last_on_empty_queue_returns_none() {
		let queue = ImportQueue::<TestBlock>::default();
		assert_eq!(None, queue.peek_last().unwrap());
	}
}
