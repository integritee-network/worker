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
//! Queueing of block imports.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

pub mod block_import_queue;
pub mod error;

pub use block_import_queue::*;

use error::Result;
use std::vec::Vec;

/// Trait to push blocks to an import queue.
pub trait PushToBlockQueue<BlockType> {
	/// Push multiple blocks to the queue, ordering from the Vec is preserved.
	fn push_multiple(&self, blocks: Vec<BlockType>) -> Result<()>;

	/// Push a single block to the queue.
	fn push_single(&self, block: BlockType) -> Result<()>;
}

/// Trait to pop blocks from the import queue.
pub trait PopFromBlockQueue {
	type BlockType;

	/// Pop (i.e. removes and returns) all but the last block from the import queue.
	fn pop_all_but_last(&self) -> Result<Vec<Self::BlockType>>;

	/// Pop (i.e. removes and returns) all blocks from the import queue.
	fn pop_all(&self) -> Result<Vec<Self::BlockType>>;

	/// Pop (front) until specified block is found. If no block matches, empty Vec is returned.
	fn pop_until<Predicate>(&self, predicate: Predicate) -> Result<Vec<Self::BlockType>>
	where
		Predicate: Fn(&Self::BlockType) -> bool;

	/// Pop (front) queue. Returns None if queue is empty.
	fn pop_front(&self) -> Result<Option<Self::BlockType>>;
}

/// Trait to peek blocks in the import queue without altering the queue.
pub trait PeekBlockQueue {
	type BlockType: Clone;

	/// Search the queue with a given predicate and return a reference to the first element that matches.
	/// Returns None if nothing matches.
	fn peek_find<Predicate>(&self, predicate: Predicate) -> Result<Option<Self::BlockType>>
	where
		Predicate: Fn(&Self::BlockType) -> bool;

	/// Peeks the last element in the queue (aka the newest one, last to be popped).
	/// Returns None if queue is empty.
	fn peek_last(&self) -> Result<Option<Self::BlockType>>;

	/// Peek the queue size (i.e. number of elements the queue contains).
	fn peek_queue_size(&self) -> Result<usize>;
}
