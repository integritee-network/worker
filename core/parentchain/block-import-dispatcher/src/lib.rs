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
//! Dispatching of block imports.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

pub mod error;
pub mod immediate_dispatcher;
pub mod triggered_dispatcher;

#[cfg(feature = "mocks")]
pub mod trigger_parentchain_block_import_mock;

use crate::triggered_dispatcher::TriggerParentchainBlockImport;
use core::marker::PhantomData;
use error::{Error, Result};
use std::{sync::Arc, vec::Vec};

/// Trait to dispatch blocks for import into the local light-client.
pub trait DispatchBlockImport<SignedBlockType> {
	/// Dispatch blocks to be imported.
	///
	/// The blocks may be imported immediately, get queued, delayed or grouped.
	fn dispatch_import(&self, blocks: Vec<SignedBlockType>) -> Result<()>;
}

/// Wrapper struct for the actual dispatchers. Allows to define one global type for
///  a dispatcher even though only one dispatcher is used.
pub struct BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType> {
	triggered_dispatcher: Option<Arc<TriggeredDispatcher>>,
	immediate_dispatcher: Option<Arc<ImmediateDispatcher>>,
	_phantom: PhantomData<SignedBlockType>,
}

impl<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType>
	BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType>
where
	TriggeredDispatcher: TriggerParentchainBlockImport<SignedBlockType>,
{
	pub fn new_triggered_dispatcher(triggered_dispatcher: Arc<TriggeredDispatcher>) -> Self {
		Self {
			triggered_dispatcher: Some(triggered_dispatcher),
			immediate_dispatcher: None,
			_phantom: Default::default(),
		}
	}

	pub fn new_immediate_dispatcher(immediate_dispatcher: Arc<ImmediateDispatcher>) -> Self {
		Self {
			triggered_dispatcher: None,
			immediate_dispatcher: Some(immediate_dispatcher),
			_phantom: Default::default(),
		}
	}

	pub fn triggered_dispatcher(&self) -> Option<Arc<TriggeredDispatcher>> {
		self.triggered_dispatcher.clone()
	}

	pub fn immediate_dispatcher(&self) -> Option<Arc<ImmediateDispatcher>> {
		self.immediate_dispatcher.clone()
	}
}

impl<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType> DispatchBlockImport<SignedBlockType>
	for BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType>
where
	TriggeredDispatcher: DispatchBlockImport<SignedBlockType>,
	ImmediateDispatcher: DispatchBlockImport<SignedBlockType>,
{
	fn dispatch_import(&self, blocks: Vec<SignedBlockType>) -> Result<()> {
		if self.triggered_dispatcher.is_some() && self.immediate_dispatcher.is_some() {
			return Err(Error::CanNotAssignTwoDispatcher)
		}

		if let Some(triggered_dispatcher) = &self.triggered_dispatcher {
			triggered_dispatcher.dispatch_import(blocks)
		} else if let Some(immediate_dispatcher) = &self.immediate_dispatcher {
			immediate_dispatcher.dispatch_import(blocks)
		} else {
			Err(Error::NoDispatcherAssigned)
		}
	}
}
