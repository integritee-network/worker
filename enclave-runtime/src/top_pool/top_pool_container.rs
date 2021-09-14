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

use crate::top_pool::{pool_types::BPool, primitives::TrustedOperationPool};
use sp_core::H256;
use std::{
	marker::PhantomData,
	sync::{
		atomic::{AtomicPtr, Ordering},
		Arc, SgxMutex,
	},
};

static GLOBAL_TOP_CONTAINER: AtomicContainer = AtomicContainer::new();

/// getter trait for the trusted operation pool
pub trait GetTopPool: Send + Sync + 'static {
	type TrustedOperationPool: TrustedOperationPool<Hash = H256> + 'static;

	fn get(&self) -> Option<&'static SgxMutex<Self::TrustedOperationPool>>;
}

/// Global container wrapper for the trusted operation (TOP) pool
/// must be initialized before use, calling the `initialize()` method
pub struct GlobalTopPoolContainer;

impl GlobalTopPoolContainer {
	pub fn initialize(trusted_operation_pool: <Self as GetTopPool>::TrustedOperationPool) {
		GLOBAL_TOP_CONTAINER.store(trusted_operation_pool)
	}
}

impl GetTopPool for GlobalTopPoolContainer {
	type TrustedOperationPool = BPool;

	fn get(&self) -> Option<&'static SgxMutex<Self::TrustedOperationPool>> {
		GLOBAL_TOP_CONTAINER.load()
	}
}

/// Top pool container that owns the container and does not make use of
/// global state (like the `GlobalTopPoolContainer` does)
pub struct TopPoolContainer<TopPool> {
	atomic_container: AtomicContainer,
	_pool: PhantomData<TopPool>,
}

impl<TopPool> TopPoolContainer<TopPool>
where
	TopPool: TrustedOperationPool<Hash = H256> + 'static,
{
	pub fn new(trusted_operation_pool: TopPool) -> Self {
		let container =
			TopPoolContainer { atomic_container: AtomicContainer::new(), _pool: PhantomData };
		container.atomic_container.store(trusted_operation_pool);
		container
	}
}

impl<TopPool> GetTopPool for TopPoolContainer<TopPool>
where
	TopPool: TrustedOperationPool<Hash = H256> + 'static,
{
	type TrustedOperationPool = TopPool;

	fn get(&self) -> Option<&'static SgxMutex<Self::TrustedOperationPool>> {
		self.atomic_container.load()
	}
}

/// Generic atomic container that holds an item in a container
pub struct AtomicContainer {
	atomic_ptr: AtomicPtr<()>,
}

impl AtomicContainer {
	pub const fn new() -> Self {
		AtomicContainer { atomic_ptr: AtomicPtr::new(0 as *mut ()) }
	}

	/// store and item in the container
	pub fn store<T>(&self, item: T) {
		let pool_ptr = Arc::new(SgxMutex::<T>::new(item));
		let ptr = Arc::into_raw(pool_ptr);
		self.atomic_ptr.store(ptr as *mut (), Ordering::SeqCst);
	}

	/// load an item from the container, returning a mutex
	pub fn load<T>(&self) -> Option<&'static SgxMutex<T>> {
		let ptr = self.atomic_ptr.load(Ordering::SeqCst) as *mut SgxMutex<T>;
		if ptr.is_null() {
			None
		} else {
			Some(unsafe { &*ptr })
		}
	}
}
