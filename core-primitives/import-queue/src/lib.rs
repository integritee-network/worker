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
//! Queueing of item imports.

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

pub mod error;
pub mod import_queue;

pub use import_queue::*;

use error::Result;
use std::vec::Vec;

/// Trait to push items such as blocks to an import queue.
pub trait PushToQueue<Item> {
	/// Push multiple items to the queue, ordering from the Vec is preserved.
	fn push_multiple(&self, item: Vec<Item>) -> Result<()>;

	/// Push a single item to the queue.
	fn push_single(&self, item: Item) -> Result<()>;
}

/// Trait to pop items from the import queue.
pub trait PopFromQueue {
	type ItemType;

	/// Pop (i.e. removes and returns) all but the last item from the import queue.
	fn pop_all_but_last(&self) -> Result<Vec<Self::ItemType>>;

	/// Pop (i.e. removes and returns) all items from the import queue.
	fn pop_all(&self) -> Result<Vec<Self::ItemType>>;

	/// Pop (front) until specified item is found. If no item matches, empty Vec is returned.
	fn pop_until<Predicate>(&self, predicate: Predicate) -> Result<Vec<Self::ItemType>>
	where
		Predicate: Fn(&Self::ItemType) -> bool;

	/// Pop (front) queue. Returns None if queue is empty.
	fn pop_front(&self) -> Result<Option<Self::ItemType>>;

	/// Pop (front) queue until a specific amount of pops has been reached
	fn pop_from_front_until(&self, amount: usize) -> Result<Vec<Self::ItemType>>;
}

/// Trait to peek items in the import queue without altering the queue.
pub trait PeekQueue {
	type ItemType: Clone;

	/// Search the queue with a given predicate and return a reference to the first element that matches.
	/// Returns None if nothing matches.
	fn peek_find<Predicate>(&self, predicate: Predicate) -> Result<Option<Self::ItemType>>
	where
		Predicate: Fn(&Self::ItemType) -> bool;

	/// Peeks the last element in the queue (aka the newest one, last to be popped).
	/// Returns None if queue is empty.
	fn peek_last(&self) -> Result<Option<Self::ItemType>>;

	/// Peek the queue size (i.e. number of elements the queue contains).
	fn peek_queue_size(&self) -> Result<usize>;
}
