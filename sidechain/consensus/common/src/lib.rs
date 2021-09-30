//! Common stuff that could be shared across multiple consensus engines

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use itp_types::OpaqueCall;
use its_primitives::traits::{ShardIdentifierFor, SignedBlock as SignedSidechainBlock};
use sp_runtime::traits::Block as ParentchainBlock;
use std::{time::Duration, vec::Vec};

mod block_import;
mod error;

pub use block_import::*;
pub use error::*;

pub trait Verifier<PB, SB>: Send + Sync
where
	PB: ParentchainBlock,
	SB: SignedSidechainBlock,
{
	/// Contains all the relevant data needed for block import
	type BlockImportParams;

	/// Context used to derive slot relevant data
	type Context;

	/// Verify the given data and return the `BlockImportParams` if successful
	fn verify(
		&mut self,
		block: SB,
		parentchain_header: &PB::Header,
		ctx: &Self::Context,
	) -> Result<Self::BlockImportParams>;
}

/// Environment for a Consensus instance.
///
/// Creates proposer instance.
pub trait Environment<B: ParentchainBlock, SB: SignedSidechainBlock> {
	/// The proposer type this creates.
	type Proposer: Proposer<B, SB> + Send;
	/// Error which can occur upon creation.
	type Error: From<Error> + std::fmt::Debug + 'static;

	/// Initialize the proposal logic on top of a specific header.
	fn init(
		&mut self,
		parent_header: B::Header,
		shard: ShardIdentifierFor<SB>,
	) -> std::result::Result<Self::Proposer, Self::Error>;
}

pub trait Proposer<B: ParentchainBlock, SB: SignedSidechainBlock> {
	fn propose(&self, max_duration: Duration) -> Result<Proposal<SB>>;
}

/// A proposal that is created by a [`Proposer`].
pub struct Proposal<SidechainBlock: SignedSidechainBlock> {
	/// The sidechain block that was build.
	pub block: SidechainBlock,
	/// Parentchain state transitions triggered by sidechain state transitions.
	///
	/// Any sidechain stf that invokes a parentchain stf must not commit its state change
	/// before the parentchain effect has been finalized.
	pub parentchain_effects: Vec<OpaqueCall>,
}
