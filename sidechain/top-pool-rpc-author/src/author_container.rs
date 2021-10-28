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

#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use std::sync::Mutex;

use crate::{
	atomic_container::AtomicContainer,
	traits::{FullAuthor, GetAuthor},
};
use std::{marker::PhantomData, sync::Arc};

/// Author container that owns the container and does not make use of
/// global state (like the `GlobalAuthorContainer` does)
pub struct AuthorContainer<AuthorT> {
	atomic_container: AtomicContainer,
	_pool: PhantomData<AuthorT>,
}

impl<AuthorT> AuthorContainer<AuthorT>
where
	AuthorT: FullAuthor,
{
	pub fn new(trusted_operation_pool: Arc<AuthorT>) -> Self {
		let container =
			AuthorContainer { atomic_container: AtomicContainer::new(), _pool: PhantomData };
		container.atomic_container.store(trusted_operation_pool);
		container
	}
}

impl<AuthorT> GetAuthor for AuthorContainer<AuthorT>
where
	AuthorT: FullAuthor,
{
	type AuthorType = AuthorT;

	fn get(&self) -> Option<&'static Mutex<Arc<Self::AuthorType>>> {
		self.atomic_container.load()
	}
}
