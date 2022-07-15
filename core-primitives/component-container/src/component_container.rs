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

use crate::{
	atomic_container::AtomicContainer,
	error::{Error, Result},
};
use std::{
	format,
	marker::PhantomData,
	string::{String, ToString},
	sync::Arc,
};

/// Trait to initialize a generic component.
pub trait ComponentInitializer {
	type ComponentType;

	fn initialize(&self, component: Arc<Self::ComponentType>);
}

/// Trait to retrieve a generic component.
pub trait ComponentGetter {
	type ComponentType;

	/// Try to get a specific component, returns `None` if component has not been initialized.
	fn get(&self) -> Result<Arc<Self::ComponentType>>;
}

/// Workaround to make `new()` a `const fn`.
/// Is required in order to have the `ComponentContainer` in a static variable.
struct Invariant<T>(T);

/// Component container implementation. Can be used in a global static context.
pub struct ComponentContainer<Component> {
	container: AtomicContainer,
	component_name: &'static str,
	_phantom: PhantomData<Invariant<Component>>,
}

impl<Component> ComponentContainer<Component> {
	/// Create a new container instance.
	///
	/// Has to be `const` in order to be used in a `static` context.
	pub const fn new(component_name: &'static str) -> Self {
		ComponentContainer {
			container: AtomicContainer::new(),
			component_name,
			_phantom: PhantomData,
		}
	}
}

impl<Component> ComponentInitializer for ComponentContainer<Component> {
	type ComponentType = Component;

	fn initialize(&self, component: Arc<Self::ComponentType>) {
		self.container.store(component)
	}
}

impl<Component> ToString for ComponentContainer<Component> {
	fn to_string(&self) -> String {
		format!("{} component", self.component_name)
	}
}

impl<Component> ComponentGetter for ComponentContainer<Component> {
	type ComponentType = Component;

	fn get(&self) -> Result<Arc<Self::ComponentType>> {
		let component_mutex: &Mutex<Arc<Self::ComponentType>> = self
			.container
			.load()
			.ok_or_else(|| Error::ComponentNotInitialized(self.to_string()))?;
		Ok(component_mutex.lock().expect("Lock poisoning").clone())
	}
}
