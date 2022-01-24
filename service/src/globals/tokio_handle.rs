/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use lazy_static::lazy_static;
use parking_lot::RwLock;
use tokio::runtime::Handle;

lazy_static! {
	static ref TOKIO_HANDLE: RwLock<Option<tokio::runtime::Runtime>> = RwLock::new(None);
}

/// Wrapper for accessing a tokio handle
pub trait GetTokioHandle {
	fn get_handle(&self) -> Handle;
}

/// implementation, using a static global variable internally
///
pub struct GlobalTokioHandle;

/// these are the static (global) accessors
/// reduce their usage where possible and use an instance of TokioHandleAccessorImpl or the trait
impl GlobalTokioHandle {
	/// this needs to be called once at application startup!
	pub fn initialize() {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.enable_all()
			.worker_threads(2)
			.build()
			.unwrap();
		*TOKIO_HANDLE.write() = Some(rt);
	}

	/// static / global getter of the handle (try to keep private!, use trait to access handle)
	fn read_handle() -> Handle {
		TOKIO_HANDLE
			.read()
			.as_ref()
			.expect("Tokio handle has not been initialized!")
			.handle()
			.clone()
	}
}

impl GetTokioHandle for GlobalTokioHandle {
	fn get_handle(&self) -> Handle {
		GlobalTokioHandle::read_handle()
	}
}

/// Implementation for a scoped Tokio handle.
///
///
pub struct ScopedTokioHandle {
	tokio_runtime: tokio::runtime::Runtime,
}

impl Default for ScopedTokioHandle {
	fn default() -> Self {
		ScopedTokioHandle { tokio_runtime: tokio::runtime::Runtime::new().unwrap() }
	}
}

impl GetTokioHandle for ScopedTokioHandle {
	fn get_handle(&self) -> Handle {
		self.tokio_runtime.handle().clone()
	}
}

#[cfg(test)]
mod tests {

	use super::*;

	#[tokio::test]
	async fn given_initialized_tokio_handle_when_runtime_goes_out_of_scope_then_async_handle_is_valid(
	) {
		// initialize the global handle
		// be aware that if you write more tests here, the global state will be shared across multiple threads
		// which cargo test spawns. So it can lead to failing tests.
		// solution: either get rid of the global state, or write all test functionality in this single test function
		{
			GlobalTokioHandle::initialize();
		}

		let handle = GlobalTokioHandle.get_handle();

		let result = handle.spawn_blocking(|| "now running on a worker thread").await;

		assert!(result.is_ok());
		assert!(!result.unwrap().is_empty())
	}
}
