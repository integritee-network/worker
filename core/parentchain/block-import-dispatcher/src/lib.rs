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

use error::{Error, Result};
use std::vec::Vec;

/// Trait to dispatch blocks for import into the local light-client.
pub trait DispatchBlockImport {
	type SignedBlockType;

	/// Dispatch blocks to be imported.
	///
	/// The blocks may be imported immediately, get queued, delayed or grouped.
	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()>;
}

/// Wrapper struct for the actual dispatchers. Allows to define one global type for
///  a dispatcher even though only one dispatcher is used.
pub struct BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher> {
	triggered_dispatcher: Option<TriggeredDispatcher>,
	immediate_dispatcher: Option<ImmediateDispatcher>,
}

impl<TriggeredDispatcher, ImmediateDispatcher>
	BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher>
where
	TriggeredDispatcher: DispatchBlockImport + TriggerParentchainBlockImport,
	ImmediateDispatcher: DispatchBlockImport,
{
	pub fn new_triggered_dispatcher(triggered_dispatcher: TriggeredDispatcher) -> Self {
		Self { triggered_dispatcher: Some(triggered_dispatcher), immediate_dispatcher: None }
	}

	pub fn new_immediate_dispatcher(immediate_dispatcher: ImmediateDispatcher) -> Self {
		Self { triggered_dispatcher: None, immediate_dispatcher: Some(immediate_dispatcher) }
	}

	pub fn triggered_dispatcher(self) -> Option<TriggeredDispatcher> {
		self.triggered_dispatcher
	}

	pub fn immediate_dispatcher(self) -> Option<ImmediateDispatcher> {
		self.immediate_dispatcher
	}
}

impl<TriggeredDispatcher, ImmediateDispatcher> DispatchBlockImport
	for BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher>
where
	TriggeredDispatcher: DispatchBlockImport,
	ImmediateDispatcher: DispatchBlockImport,
{
	fn dispatch_import(&self, blocks: Vec<Self::SignedBlockType>) -> Result<()> {
		if self.triggered_dispatcher.is_some() && self.immediate_dispatcher.is_some() {
			return Err(Error::CanNotAssignTwoDispatcher)
		}

		if let Some(triggered_dispatcher) = self.triggered_dispatcher {
			triggered_dispatcher.dispatch_import(blocks)
		} else if let Some(immediate_dispatcher) = self.immediate_dispatcher {
			immediate_dispatcher.dispatch_import(blocks)
		} else {
			return Err(Error::NoDispatcherAssigned)
		}
	}
}
