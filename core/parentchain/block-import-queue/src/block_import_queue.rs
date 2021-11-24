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
	PopFromBlockQueue, PushToBlockQueue,
};
use std::{collections::VecDeque, vec::Vec};

/// Block import queue.
///
/// Uses RwLock internally to guard against concurrent access and ensure all operations are atomic.
pub struct BlockImportQueue<PB> {
	queue: RwLock<VecDeque<PB>>,
}

impl<PB> BlockImportQueue<PB> {
	pub fn is_empty(&self) -> Result<bool> {
		let queue_lock = self.queue.read().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.is_empty())
	}
}

impl<PB> Default for BlockImportQueue<PB> {
	fn default() -> Self {
		BlockImportQueue { queue: Default::default() }
	}
}

impl<PB> PushToBlockQueue for BlockImportQueue<PB> {
	type BlockType = PB;

	fn push_multiple(&self, blocks: Vec<PB>) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.extend(blocks);
		Ok(())
	}

	fn push_single(&self, block: PB) -> Result<()> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		queue_lock.push_back(block);
		Ok(())
	}
}

impl<PB> PopFromBlockQueue for BlockImportQueue<PB> {
	type BlockType = PB;

	fn pop_all_but_last(&self) -> Result<Vec<PB>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		let queue_length = queue_lock.len();
		if queue_length < 2 {
			return Ok(Vec::<PB>::default())
		}
		Ok(queue_lock.drain(..queue_length - 1).collect::<Vec<_>>())
	}

	fn pop_all(&self) -> Result<Vec<PB>> {
		let mut queue_lock = self.queue.write().map_err(|_| Error::PoisonedLock)?;
		Ok(queue_lock.drain(..).collect::<Vec<_>>())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

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
}
