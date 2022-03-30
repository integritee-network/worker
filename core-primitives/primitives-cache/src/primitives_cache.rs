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
use std::sync::SgxRwLockReadGuard as RwLockReadGuard;
#[cfg(all(not(feature = "std"), feature = "sgx"))]
use std::sync::SgxRwLockWriteGuard as RwLockWriteGuard;

#[cfg(feature = "std")]
use std::sync::RwLock;
#[cfg(feature = "std")]
use std::sync::RwLockReadGuard;
#[cfg(feature = "std")]
use std::sync::RwLockWriteGuard;

use std::string::{String, ToString};

use crate::{
	error::{Error, Result},
	GetPrimitives, MutatePrimitives, Primitives,
};

/// Local primitives cache.
///
/// Stores the primitives internally, protected by a RW lock for concurrent access.
#[derive(Default)]
pub struct PrimitivesCache {
	primitives_lock: RwLock<Primitives>,
}

impl PrimitivesCache {
	pub fn new(primitives_lock: RwLock<Primitives>) -> Self {
		PrimitivesCache { primitives_lock }
	}
}

impl MutatePrimitives for PrimitivesCache {
	fn load_for_mutation(&self) -> Result<RwLockWriteGuard<'_, Primitives>> {
		self.primitives_lock.write().map_err(|_| Error::LockPoisoning)
	}
}

impl GetPrimitives for PrimitivesCache {
	fn get_primitives(&self) -> Result<RwLockReadGuard<Primitives>> {
		self.primitives_lock.read().map_err(|_| Error::LockPoisoning)
	}

	fn get_mu_ra_url(&self) -> Result<String> {
		let primitives_lock = self.primitives_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(primitives_lock.mu_ra_url().to_string())
	}

	fn get_untrusted_worker_url(&self) -> Result<String> {
		let primitives_lock = self.primitives_lock.read().map_err(|_| Error::LockPoisoning)?;
		Ok(primitives_lock.untrusted_worker_url().to_string())
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use std::{sync::Arc, thread};

	#[test]
	pub fn set_primitives_works() {
		let cache = PrimitivesCache::default();
		let mut lock = cache.load_for_mutation().unwrap();
		let mu_ra_url = "hello".to_string();
		let untrusted_url = "world".to_string();
		let primitives = Primitives::new(mu_ra_url, untrusted_url);
		*lock = primitives.clone();
		std::mem::drop(lock);
		assert_eq!(primitives, *cache.get_primitives().unwrap());
	}

	#[test]
	pub fn concurrent_read_access_blocks_until_write_is_done() {
		let cache = Arc::new(PrimitivesCache::default());
		let mu_ra_url = "hello".to_string();
		let untrusted_url = "world".to_string();
		let primitives = Primitives::new(mu_ra_url, untrusted_url);

		let mut write_lock = cache.load_for_mutation().unwrap();

		// Spawn a new thread that reads the primitives.
		// This thread should be blocked until the write lock is released, i.e. until
		// the new primitves are written. We can verify this, by trying to read the primitives variable
		// that will be inserted further down below.
		let new_thread_cache = cache.clone();
		let primitives_one = primitives.clone();
		let join_handle = thread::spawn(move || {
			let read = new_thread_cache.get_primitives().unwrap();
			assert_eq!(primitives_one, *read);
		});

		*write_lock = primitives;
		std::mem::drop(write_lock);

		join_handle.join().unwrap();
	}
}
