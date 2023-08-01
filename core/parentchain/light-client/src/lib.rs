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

//! Light-client crate that imports and verifies parentchain blocks.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// Re-export useful types.
pub use finality_grandpa::BlockNumberOps;
pub use sp_consensus_grandpa::{AuthorityList, SetId};

use crate::light_validation_state::LightValidationState;
use error::Error;
use sp_consensus_grandpa::{AuthorityId, AuthorityWeight, ConsensusLog, GRANDPA_ENGINE_ID};
use sp_runtime::{
	generic::{Digest, OpaqueDigestItemId, SignedBlock},
	traits::{Block as ParentchainBlockTrait, Header as HeaderTrait},
	OpaqueExtrinsic,
};
use std::{path::Path, vec::Vec};

pub mod concurrent_access;
pub mod error;
pub mod finality;
pub mod justification;
pub mod light_client_init_params;
pub mod light_validation;
pub mod light_validation_state;
pub mod state;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod io;

#[cfg(any(test, feature = "mocks"))]
pub mod mocks;

pub type RelayId = u64;

pub type AuthorityListRef<'a> = &'a [(AuthorityId, AuthorityWeight)];

// disambiguate associated types
/// Block number type
pub type NumberFor<Block> = <<Block as ParentchainBlockTrait>::Header as HeaderTrait>::Number;
/// Hash type of Block
pub type HashFor<Block> = <<Block as ParentchainBlockTrait>::Header as HeaderTrait>::Hash;
/// Hashing function used to produce `HashOf<Block>`
pub type HashingFor<Block> = <<Block as ParentchainBlockTrait>::Header as HeaderTrait>::Hashing;

/// Validator trait
pub trait Validator<Block: ParentchainBlockTrait>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn submit_block(&mut self, signed_block: &SignedBlock<Block>) -> Result<(), Error>;

	fn check_xt_inclusion(&mut self, block: &Block) -> Result<(), Error>;

	fn get_state(&self) -> &LightValidationState<Block>;
}

pub trait ExtrinsicSender {
	/// Sends encoded extrinsics to the parentchain and cache them internally for later confirmation.
	fn send_extrinsics(&mut self, extrinsics: Vec<OpaqueExtrinsic>) -> Result<(), Error>;
}

pub trait LightClientState<Block: ParentchainBlockTrait> {
	fn num_xt_to_be_included(&self) -> Result<usize, Error>;

	fn genesis_hash(&self) -> Result<HashFor<Block>, Error>;

	fn latest_finalized_header(&self) -> Result<Block::Header, Error>;

	// Todo: Check if we still need this after #423
	fn penultimate_finalized_block_header(&self) -> Result<Block::Header, Error>;
}

pub trait LightClientSealing {
	type LightClientState;

	fn seal(&self, state: &Self::LightClientState) -> Result<(), Error>;
	fn unseal(&self) -> Result<Self::LightClientState, Error>;
	fn exists(&self) -> bool;
	fn path(&self) -> &Path;
}

pub fn grandpa_log<Block: ParentchainBlockTrait>(
	digest: &Digest,
) -> Option<ConsensusLog<NumberFor<Block>>> {
	let id = OpaqueDigestItemId::Consensus(&GRANDPA_ENGINE_ID);
	digest.convert_first(|l| l.try_to::<ConsensusLog<NumberFor<Block>>>(id))
}
