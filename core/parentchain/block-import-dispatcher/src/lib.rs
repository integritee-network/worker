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
use error::{Error, Result};
use std::{sync::Arc, vec::Vec};

/// Trait to dispatch blocks for import into the local light-client.
pub trait DispatchBlockImport<SignedBlockType> {
	/// Dispatch blocks to be imported.
	///
	/// The blocks may be imported immediately, get queued, delayed or grouped.
	fn dispatch_import(&self, blocks: Vec<SignedBlockType>, events: Vec<Vec<u8>>) -> Result<()>;
}

/// Wrapper for the actual dispatchers. Allows to define one global type for
/// both dispatchers without changing the global variable when switching
/// the dispatcher type. It also allows for empty dispatchers, for use cases that
/// do not need block syncing for a specific parentchain type.
pub enum BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher> {
	TriggeredDispatcher(Arc<TriggeredDispatcher>),
	ImmediateDispatcher(Arc<ImmediateDispatcher>),
	EmptyDispatcher,
}

impl<TriggeredDispatcher, ImmediateDispatcher>
	BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher>
where
	TriggeredDispatcher: TriggerParentchainBlockImport,
{
	pub fn new_triggered_dispatcher(triggered_dispatcher: Arc<TriggeredDispatcher>) -> Self {
		BlockImportDispatcher::TriggeredDispatcher(triggered_dispatcher)
	}

	pub fn new_immediate_dispatcher(immediate_dispatcher: Arc<ImmediateDispatcher>) -> Self {
		BlockImportDispatcher::ImmediateDispatcher(immediate_dispatcher)
	}

	pub fn new_empty_dispatcher() -> Self {
		BlockImportDispatcher::EmptyDispatcher
	}

	pub fn triggered_dispatcher(&self) -> Option<Arc<TriggeredDispatcher>> {
		match self {
			BlockImportDispatcher::TriggeredDispatcher(triggered_dispatcher) =>
				Some(triggered_dispatcher.clone()),
			_ => None,
		}
	}

	pub fn immediate_dispatcher(&self) -> Option<Arc<ImmediateDispatcher>> {
		match self {
			BlockImportDispatcher::ImmediateDispatcher(immediate_dispatcher) =>
				Some(immediate_dispatcher.clone()),
			_ => None,
		}
	}
}

impl<TriggeredDispatcher, ImmediateDispatcher, SignedBlockType> DispatchBlockImport<SignedBlockType>
	for BlockImportDispatcher<TriggeredDispatcher, ImmediateDispatcher>
where
	TriggeredDispatcher: DispatchBlockImport<SignedBlockType>,
	ImmediateDispatcher: DispatchBlockImport<SignedBlockType>,
{
	fn dispatch_import(&self, blocks: Vec<SignedBlockType>, events: Vec<Vec<u8>>) -> Result<()> {
		match self {
			BlockImportDispatcher::TriggeredDispatcher(dispatcher) => {
				log::info!("TRIGGERED DISPATCHER MATCH");
				dispatcher.dispatch_import(blocks, events)
			},
			BlockImportDispatcher::ImmediateDispatcher(dispatcher) => {
				log::info!("IMMEDIATE DISPATCHER MATCH");
				dispatcher.dispatch_import(blocks, events)
			},
			BlockImportDispatcher::EmptyDispatcher => {
				log::info!("EMPTY DISPATCHER DISPATCHER MATCH");
				Err(Error::NoDispatcherAssigned)
			},
		}
	}
}
