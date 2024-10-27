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

#![cfg_attr(not(feature = "std"), no_std)]
#![feature(assert_matches)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

use its_primitives::types::header::SidechainHeader;

use crate::error::Result;

pub use nonce_cache::NonceCache;

pub mod block_header_cache;
pub mod error;

/// Nonce type (newtype wrapper for NonceValue)
#[derive(Default, Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct CachedSidechainBlockHeader(pub SidechainHeader);
/// Trait to mutate a BlockHeader.
///
/// Used in a combination of loading a lock and then writing the updated
/// value back, returning the lock again.
pub trait MutateBlockHeader {
	/// load a BlockHeader with the intention to mutate it. lock is released once it goes out of scope
	fn load_for_mutation(&self) -> Result<RwLockWriteGuard<'_, CachedSidechainBlockHeader>>;
}

/// Trait to get a BlockHeader.
///
///
pub trait GetBlockHeader {
	fn get_block_header(&self) -> Result<CachedSidechainBlockHeader>;
}
