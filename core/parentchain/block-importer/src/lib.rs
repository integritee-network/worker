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
//! Parentchain block importing logic.
#![feature(trait_alias)]
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

pub mod block_importer;
pub mod error;

#[cfg(feature = "mocks")]
pub mod block_importer_mock;

pub use block_importer::*;

use error::Result;
use std::vec::Vec;

/// Block import from the parentchain.
pub trait ImportParentchainBlocks {
	type SignedBlockType: Clone;

	/// Import parentchain blocks to the light-client (validator):
	/// * Scans the blocks for relevant extrinsics
	/// * Validates and execute those extrinsics, mutating state
	/// * Includes block headers into the light client
	/// * Sends `PROCESSED_PARENTCHAIN_BLOCK` extrinsics that include the merkle root of all processed calls
	fn import_parentchain_blocks(
		&self,
		blocks_to_import: Vec<Self::SignedBlockType>,
		events_to_import: Vec<Vec<u8>>,
	) -> Result<()>;
}
