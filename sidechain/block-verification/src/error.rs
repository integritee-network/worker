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

//! Error types in sidechain consensus

use itp_types::BlockHash as ParentchainBlockHash;
use its_primitives::types::{block::BlockHash as SidechainBlockHash, BlockNumber};
use std::string::String;

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub use thiserror_sgx as thiserror;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	#[error("Message sender {0} is not a valid authority")]
	InvalidAuthority(String),
	#[error("Could not get authorities: {0:?}.")]
	CouldNotGetAuthorities(String),
	#[error("Bad parentchain block (Hash={0}). Reason: {1}")]
	BadParentchainBlock(ParentchainBlockHash, String),
	#[error("Bad sidechain block (Hash={0}). Reason: {1}")]
	BadSidechainBlock(SidechainBlockHash, String),
	#[error("Could not import new block due to {2}. (Last imported by number: {0:?})")]
	BlockAncestryMismatch(BlockNumber, SidechainBlockHash, String),
	#[error("Could not import new block. Expected first block, but found {0}. {1:?}")]
	InvalidFirstBlock(BlockNumber, String),
	#[error("Could not import block (number: {0}). A block with this number is already imported (current state block number: {1})")]
	BlockAlreadyImported(BlockNumber, BlockNumber),
}
