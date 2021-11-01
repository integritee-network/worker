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
	author::{Author, AuthorTopFilter},
	pool_types::BPool,
	traits::GetAuthor,
};
use itp_stf_state_handler::GlobalFileStateHandler;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::sync::Arc;

static GLOBAL_AUTHOR_CONTAINER: AtomicContainer = AtomicContainer::new();

/// Global container wrapper for the RPC author
/// must be initialized before use, calling the `initialize()` method
pub struct GlobalAuthorContainer;

impl GlobalAuthorContainer {
	pub fn initialize(trusted_operation_pool: Arc<<Self as GetAuthor>::AuthorType>) {
		GLOBAL_AUTHOR_CONTAINER.store(trusted_operation_pool)
	}
}

impl GetAuthor for GlobalAuthorContainer {
	type AuthorType = Author<BPool, AuthorTopFilter, GlobalFileStateHandler, Rsa3072KeyPair>;

	fn get(&self) -> Option<Arc<Self::AuthorType>> {
		let author_mutex: &'static Mutex<Arc<Self::AuthorType>> = GLOBAL_AUTHOR_CONTAINER.load()?;

		Some(author_mutex.lock().unwrap().clone())
	}
}
