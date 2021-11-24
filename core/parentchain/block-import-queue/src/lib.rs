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

/// Trait to push parentchain blocks to an import queue.
pub trait PushToBlockQueue {
	type BlockType;

	/// Push multiple blocks to the queue, ordering from the Vec is preserved.
	fn push_multiple(&self, blocks: Vec<Self::BlockType>) -> Result<()>;

	/// Push a single block to the queue.
	fn push_single(&self, block: Self::BlockType) -> Result<()>;
}

/// Trait to pop parentchain blocks from the import queue.
pub trait PopFromBlockQueue {
	type BlockType;

	/// Pop (i.e. removes and returns) all but the last block from the import queue
	fn pop_all_but_last(&self) -> Result<Vec<Self::BlockType>>;

	/// Pop (i.e. removes and returns) all blocks from the import queue
	fn pop_all(&self) -> Result<Vec<Self::BlockType>>;
}
