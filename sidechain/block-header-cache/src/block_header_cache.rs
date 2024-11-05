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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLock as RwLock;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

#[cfg(feature = "std")]
use std::sync::RwLock;
#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;

use crate::{
	error::{Error, Result},
	CachedSidechainBlockHeader, GetSidechainBlockHeader, MutateSidechainBlockHeader,
};

/// Local header cache
///
/// stores the header internally, protected by a RW lock for concurrent access
#[derive(Default)]
pub struct SidechainBlockHeaderCache<Header> {
	block_header_lock: RwLock<CachedSidechainBlockHeader<Header>>,
}

impl<Header> SidechainBlockHeaderCache<Header> {
	pub fn new(block_header_lock: RwLock<CachedSidechainBlockHeader<Header>>) -> Self {
		SidechainBlockHeaderCache { block_header_lock }
	}
}

impl<Header> MutateSidechainBlockHeader<Header> for SidechainBlockHeaderCache<Header> {
	fn load_for_mutation(
		&self,
	) -> Result<RwLockWriteGuard<'_, CachedSidechainBlockHeader<Header>>> {
		self.block_header_lock.write().map_err(|_| Error::LockPoisoning)
	}
}

impl<Header: Copy> GetSidechainBlockHeader<Header> for SidechainBlockHeaderCache<Header> {
	fn get_header(&self) -> Result<CachedSidechainBlockHeader<Header>> {
		let header_lock = self.block_header_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(*header_lock)
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use its_primitives::{traits::Header, types::header::SidechainHeader};
	use std::{sync::Arc, thread};

	#[test]
	pub fn cache_defaults_correctly() {
		let cache = SidechainBlockHeaderCache::default();
		assert_eq!(
			CachedSidechainBlockHeader(SidechainHeader::default()),
			cache.get_header().unwrap()
		);
	}

	#[test]
	pub fn set_block_header_works() {
		let block_header_cache = SidechainBlockHeaderCache::default();
		let mut block_header_lock = block_header_cache.load_for_mutation().unwrap();
		let desired_header = SidechainHeader::new(
			42,
			Default::default(),
			Default::default(),
			Default::default(),
			53,
		);

		*block_header_lock = CachedSidechainBlockHeader(desired_header);
		std::mem::drop(block_header_lock);
		assert_eq!(
			CachedSidechainBlockHeader(desired_header),
			block_header_cache.get_header().unwrap()
		);
	}

	#[test]
	pub fn concurrent_read_access_blocks_until_write_is_done() {
		let block_header_cache = Arc::new(SidechainBlockHeaderCache::default());

		let mut block_header_write_lock = block_header_cache.load_for_mutation().unwrap();

		let desired_header = SidechainHeader::new(
			42,
			Default::default(),
			Default::default(),
			Default::default(),
			53,
		);
		// spawn a new thread that reads the header
		// this thread should be blocked until the write lock is released, i.e. until
		// the new header is written. We can verify this, by trying to read that header variable
		// that will be inserted further down below
		let new_thread_block_header_cache = block_header_cache.clone();
		let join_handle = thread::spawn(move || {
			let block_header_read = new_thread_block_header_cache.get_header().unwrap();
			assert_eq!(CachedSidechainBlockHeader(desired_header), block_header_read);
		});

		*block_header_write_lock = CachedSidechainBlockHeader(desired_header);
		std::mem::drop(block_header_write_lock);

		join_handle.join().unwrap();
	}
}
