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

use crate::{
	rpc::author::{
		atomic_container::AtomicContainer, author::Author, AuthorApi, OnBlockCreated, SendState,
	},
	top_pool::pool_types::BPool,
};
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sp_core::H256;
use std::{
	marker::PhantomData,
	sync::{Arc, SgxMutex},
};

static GLOBAL_AUTHOR_CONTAINER: AtomicContainer = AtomicContainer::new();

/// getter trait for the RPC author
pub trait GetAuthor: Send + Sync + 'static {
	type AuthorType: AuthorApi<H256, H256>
		+ SendState<Hash = H256>
		+ OnBlockCreated<Hash = H256>
		+ Send
		+ Sync
		+ 'static;

	fn get(&self) -> Option<&'static SgxMutex<Arc<Self::AuthorType>>>;
}

/// Global container wrapper for the RPC author
/// must be initialized before use, calling the `initialize()` method
pub struct GlobalAuthorContainer;

impl GlobalAuthorContainer {
	pub fn initialize(trusted_operation_pool: Arc<<Self as GetAuthor>::AuthorType>) {
		GLOBAL_AUTHOR_CONTAINER.store(trusted_operation_pool)
	}
}

impl GetAuthor for GlobalAuthorContainer {
	type AuthorType = Author<BPool, Rsa3072KeyPair>;

	fn get(&self) -> Option<&'static SgxMutex<Arc<Self::AuthorType>>> {
		GLOBAL_AUTHOR_CONTAINER.load()
	}
}

/// Author container that owns the container and does not make use of
/// global state (like the `GlobalAuthorContainer` does)
pub struct AuthorContainer<AuthorT> {
	atomic_container: AtomicContainer,
	_pool: PhantomData<AuthorT>,
}

impl<AuthorT> AuthorContainer<AuthorT>
where
	AuthorT: AuthorApi<H256, H256>
		+ SendState<Hash = H256>
		+ OnBlockCreated<Hash = H256>
		+ Send
		+ Sync
		+ 'static,
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
	AuthorT: AuthorApi<H256, H256>
		+ SendState<Hash = H256>
		+ OnBlockCreated<Hash = H256>
		+ Send
		+ Sync
		+ 'static,
{
	type AuthorType = AuthorT;

	fn get(&self) -> Option<&'static SgxMutex<Arc<Self::AuthorType>>> {
		self.atomic_container.load()
	}
}
