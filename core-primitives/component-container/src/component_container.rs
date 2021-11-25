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

//! Generic component containers.

#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use std::sync::Mutex;

use crate::atomic_container::AtomicContainer;
use std::{marker::PhantomData, sync::Arc};

/// Trait to initialize a generic component.
pub trait ComponentInitializer {
	type ComponentT;

	fn initialize(&self, component: Arc<Self::ComponentT>);
}

/// Trait to retrieve a generic component.
pub trait ComponentGetter {
	type ComponentT;

	/// Try to get a specific component, returns `None` if component has not been initialized.
	fn get(&self) -> Option<Arc<Self::ComponentT>>;
}

/// Workaround to make `new()` a `const fn`.
/// Is required in order to have the `ComponentContainer` in a static variable.
struct Invariant<T>(T);

/// Component container implementation. Can be used in a global static context.
pub struct ComponentContainer<Component> {
	container: AtomicContainer,
	_phantom: PhantomData<Invariant<Component>>,
}

impl<Component> ComponentContainer<Component> {
	/// Create a new container instance.
	///
	/// Has to be `const` in order to be used in a `static` context.
	pub const fn new() -> Self {
		ComponentContainer { container: AtomicContainer::new(), _phantom: PhantomData }
	}
}

impl<Component> ComponentInitializer for ComponentContainer<Component> {
	type ComponentT = Component;

	fn initialize(&self, component: Arc<Self::ComponentT>) {
		self.container.store(component)
	}
}

impl<Component> ComponentGetter for ComponentContainer<Component> {
	type ComponentT = Component;

	fn get(&self) -> Option<Arc<Self::ComponentT>> {
		let component_mutex: &Mutex<Arc<Self::ComponentT>> = self.container.load()?;
		Some(component_mutex.lock().unwrap().clone())
	}
}
