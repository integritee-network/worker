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

//! Interface struct between sidechain and top pool
//!
//! This interface separates strictly between
//! * Trusted Call
//! * Trusted Getter
//! Because in the near future the top pool will be refactored to store
//! Trusted Calls & Getters separately as well (issue #229)

#![feature(trait_alias)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;
// Re-export module to properly feature gate sgx and regular std environment.
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use thiserror_sgx as thiserror;
}

pub mod call_operator;
pub mod error;
pub mod getter_operator;

#[cfg(feature = "mocks")]
pub mod call_operator_mock;

// Re-exports
pub use call_operator::TopPoolCallOperator;
pub use getter_operator::TopPoolGetterOperator;

use itp_stf_executor::traits::{StateUpdateProposer, StfExecuteTimedGettersBatch};
use itp_top_pool_author::traits::{AuthorApi, OnBlockImported, SendState};
use itp_types::H256;
use its_primitives::traits::{
	Block as SidechainBlockTrait, SignedBlock as SignedSidechainBlockTrait,
};
use its_state::{SidechainState, SidechainSystemExt, StateHash};
use sgx_externalities::SgxExternalitiesTrait;
use sp_runtime::{traits::Block as ParentchainBlockTrait, MultiSignature};
use std::{marker::PhantomData, sync::Arc};

/// Executes operations on the top pool
///
/// Operations can either be Getters or Calls
pub struct TopPoolOperationHandler<
	ParentchainBlock,
	SignedSidechainBlock,
	TopPoolAuthor,
	StfExecutor,
> {
	top_pool_author: Arc<TopPoolAuthor>,
	stf_executor: Arc<StfExecutor>,
	_phantom: PhantomData<(ParentchainBlock, SignedSidechainBlock)>,
}

impl<ParentchainBlock, SignedSidechainBlock, TopPoolAuthor, StfExecutor>
	TopPoolOperationHandler<ParentchainBlock, SignedSidechainBlock, TopPoolAuthor, StfExecutor>
where
	ParentchainBlock: ParentchainBlockTrait<Hash = H256>,
	SignedSidechainBlock:
		SignedSidechainBlockTrait<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SignedSidechainBlock::Block: SidechainBlockTrait<Public = sp_core::ed25519::Public>,
	TopPoolAuthor: AuthorApi<H256, ParentchainBlock::Hash>
		+ OnBlockImported<Hash = ParentchainBlock::Hash>
		+ SendState<Hash = ParentchainBlock::Hash>,
	StfExecutor: StateUpdateProposer + StfExecuteTimedGettersBatch,
	<StfExecutor as StateUpdateProposer>::Externalities:
		SgxExternalitiesTrait + SidechainState + SidechainSystemExt + StateHash,
{
	pub fn new(top_pool_author: Arc<TopPoolAuthor>, stf_executor: Arc<StfExecutor>) -> Self {
		TopPoolOperationHandler { top_pool_author, stf_executor, _phantom: Default::default() }
	}
}
