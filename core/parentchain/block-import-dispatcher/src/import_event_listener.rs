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

/// Listener trait to get notified when parentchain blocks get imported.
pub trait ListenToImportEvent {
	fn notify(&self);
}

#[cfg(test)]
pub(crate) mod mock {
	use super::*;
	use std::sync::{Arc, RwLock};

	#[derive(Default)]
	pub struct NotificationCounter {
		counter: RwLock<usize>,
	}

	impl NotificationCounter {
		fn increment(&self) {
			*self.counter.write().unwrap() += 1;
		}

		pub fn get_counter(&self) -> usize {
			*self.counter.read().unwrap()
		}
	}

	#[derive(Default)]
	pub(crate) struct ListenToImportEventMock {
		counter: Arc<NotificationCounter>,
	}

	impl ListenToImportEventMock {
		pub fn new(counter: Arc<NotificationCounter>) -> Self {
			Self { counter }
		}
	}

	impl ListenToImportEvent for ListenToImportEventMock {
		fn notify(&self) {
			self.counter.increment()
		}
	}
}
