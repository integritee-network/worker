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

#[cfg(feature = "std")]
use std::sync::RwLock;

use std::{string::String, vec::Vec};

/// Struct to store the updates sent through a `Connection`.
/// This allows to have tests know what update messages were sent,
/// even if the connection is closed or otherwise discarded (which happens inside handler logic)
pub struct UpdatesSink {
	received_updates: RwLock<Vec<String>>,
}

impl UpdatesSink {
	pub fn new() -> Self {
		UpdatesSink { received_updates: RwLock::new(Vec::new()) }
	}

	pub fn push_update(&self, update: String) {
		let mut updates = self.received_updates.write().unwrap();
		updates.push(update);
	}

	pub fn number_of_updates(&self) -> usize {
		self.received_updates.read().unwrap().len()
	}
}
