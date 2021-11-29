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

//! Container for a generic item, held by an AtomicPtr.

#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use std::sync::Mutex;

use std::{
	default::Default,
	sync::{
		atomic::{AtomicPtr, Ordering},
		Arc,
	},
};

/// Generic atomic container that holds an item in a container.
pub struct AtomicContainer {
	atomic_ptr: AtomicPtr<()>,
}

impl AtomicContainer {
	pub const fn new() -> Self {
		AtomicContainer { atomic_ptr: AtomicPtr::new(0 as *mut ()) }
	}

	/// Store and item in the container.
	pub fn store<T>(&self, item: T) {
		let pool_ptr = Arc::new(Mutex::<T>::new(item));
		let ptr = Arc::into_raw(pool_ptr);
		self.atomic_ptr.store(ptr as *mut (), Ordering::SeqCst);
	}

	/// Load an item from the container, returning a mutex.
	pub fn load<T>(&self) -> Option<&Mutex<T>> {
		let ptr = self.atomic_ptr.load(Ordering::SeqCst) as *mut Mutex<T>;
		if ptr.is_null() {
			None
		} else {
			Some(unsafe { &*ptr })
		}
	}
}

impl Default for AtomicContainer {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(test)]
pub mod tests {

	use super::*;
	use std::{
		ops::Deref,
		string::{String, ToString},
		vec::Vec,
	};

	#[derive(PartialEq, Eq, Clone, Debug)]
	struct TestPayload {
		name: String,
		data: Vec<u8>,
	}

	#[test]
	pub fn store_and_load_works() {
		let atomic_container = AtomicContainer::new();

		let test_payload = TestPayload {
			name: "Payload".to_string(),
			data: Vec::from("lots_of_data_to_be_stored".as_bytes()),
		};

		atomic_container.store(test_payload.clone());

		let retrieved_mutex = atomic_container.load::<TestPayload>().unwrap().lock().unwrap();
		let retrieved_payload = retrieved_mutex.deref();

		assert_eq!(&test_payload, retrieved_payload);
	}
}
