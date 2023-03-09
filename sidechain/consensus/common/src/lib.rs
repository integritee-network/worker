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

//! Common stuff that could be shared across multiple consensus engines

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(test, feature(assert_matches))]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use itp_types::OpaqueCall;
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlockTrait};
use sp_runtime::traits::Block as ParentchainBlockTrait;
use std::{time::Duration, vec::Vec};

mod block_import;
mod block_import_confirmation_handler;
mod block_import_queue_worker;
mod error;
mod header_db;
mod peer_block_sync;

// The feature flag will be removed once we use the module outside of tests.
#[cfg(test)]
mod is_descendant_of_builder;

#[cfg(test)]
mod test;

pub use block_import::*;
pub use block_import_confirmation_handler::*;
pub use block_import_queue_worker::*;
pub use error::*;
pub use peer_block_sync::*;

pub trait Verifier<ParentchainBlock, SignedSidechainBlock>: Send + Sync
where
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
{
	/// Contains all the relevant data needed for block import
	type BlockImportParams;

	/// Context used to derive slot relevant data
	type Context;

	/// Verify the given data and return the `BlockImportParams` if successful
	fn verify(
		&self,
		block: SignedSidechainBlock,
		parentchain_header: &ParentchainBlock::Header,
		ctx: &Self::Context,
	) -> Result<Self::BlockImportParams>;
}

/// Environment for a Consensus instance.
///
/// Creates proposer instance.
pub trait Environment<
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
>
{
	/// The proposer type this creates.
	type Proposer: Proposer<ParentchainBlock, SignedSidechainBlock> + Send;
	/// Error which can occur upon creation.
	type Error: From<Error> + std::fmt::Debug + 'static;

	/// Initialize the proposal logic on top of a specific header.
	fn init(
		&mut self,
		parent_header: ParentchainBlock::Header,
		shard: ShardIdentifierFor<SignedSidechainBlock>,
	) -> std::result::Result<Self::Proposer, Self::Error>;
}

pub trait Proposer<
	ParentchainBlock: ParentchainBlockTrait,
	SignedSidechainBlock: SignedSidechainBlockTrait,
>
{
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SignedSidechainBlock>>;
}

/// A proposal that is created by a [`Proposer`].
pub struct Proposal<SignedSidechainBlock: SignedSidechainBlockTrait> {
	/// The sidechain block that was build.
	pub block: SignedSidechainBlock,
	/// Parentchain state transitions triggered by sidechain state transitions.
	///
	/// Any sidechain stf that invokes a parentchain stf must not commit its state change
	/// before the parentchain effect has been finalized.
	pub parentchain_effects: Vec<OpaqueCall>,
}
