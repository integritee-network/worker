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
pub use sp_finality_grandpa::{AuthorityList, SetId};

use error::Error;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_storage::StorageProof;
use sp_finality_grandpa::{AuthorityId, AuthorityWeight, ConsensusLog, GRANDPA_ENGINE_ID};
use sp_runtime::{
	generic::{Digest, OpaqueDigestItemId, SignedBlock},
	traits::{Block as ParentchainBlockTrait, Header as HeaderTrait},
	Justifications, OpaqueExtrinsic,
};
use std::vec::Vec;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::grandpa_light_validation::GrandpaLightValidation;

pub mod concurrent_access;
pub mod error;
pub mod grandpa_light_validation;
pub mod justification;
pub mod state;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod io;

#[cfg(feature = "mocks")]
pub mod mocks;

#[cfg(all(not(feature = "mocks"), test))]
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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::concurrent_access::GlobalValidatorAccessor;

/// Global validator accessor type
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub type ValidatorAccessor<Block> = GlobalValidatorAccessor<
	GrandpaLightValidation<Block>,
	Block,
	crate::io::LightClientSeal<Block, GrandpaLightValidation<Block>>,
>;

/// Validator trait
pub trait Validator<Block: ParentchainBlockTrait>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn initialize_relay(
		&mut self,
		block_header: Block::Header,
		validator_set: AuthorityList,
		validator_set_proof: StorageProof,
	) -> Result<RelayId, Error>;

	fn submit_finalized_headers(
		&mut self,
		relay_id: RelayId,
		header: Block::Header,
		ancestry_proof: Vec<Block::Header>,
		validator_set: AuthorityList,
		validator_set_id: SetId,
		justifications: Option<Justifications>,
	) -> Result<(), Error>;

	fn submit_block(
		&mut self,
		relay_id: RelayId,
		signed_block: &SignedBlock<Block>,
	) -> Result<(), Error>;

	fn submit_xt_to_be_included(
		&mut self,
		relay_id: RelayId,
		extrinsic: OpaqueExtrinsic,
	) -> Result<(), Error>;

	/// Sends encoded extrinsics to the parentchain and cache them internally for later confirmation.
	fn send_extrinsics<OCallApi: EnclaveOnChainOCallApi>(
		&mut self,
		ocall_api: &OCallApi,
		extrinsics: Vec<OpaqueExtrinsic>,
	) -> Result<(), Error>;

	fn check_xt_inclusion(&mut self, relay_id: RelayId, block: &Block) -> Result<(), Error>;
}

pub trait LightClientState<Block: ParentchainBlockTrait> {
	fn num_xt_to_be_included(&mut self, relay_id: RelayId) -> Result<usize, Error>;

	fn genesis_hash(&self, relay_id: RelayId) -> Result<HashFor<Block>, Error>;

	fn latest_finalized_header(&self, relay_id: RelayId) -> Result<Block::Header, Error>;

	// Todo: Check if we still need this after #423
	fn penultimate_finalized_block_header(&self, relay_id: RelayId)
		-> Result<Block::Header, Error>;

	fn num_relays(&self) -> RelayId;
}

pub fn grandpa_log<Block: ParentchainBlockTrait>(
	digest: &Digest,
) -> Option<ConsensusLog<NumberFor<Block>>> {
	let id = OpaqueDigestItemId::Consensus(&GRANDPA_ENGINE_ID);
	digest.convert_first(|l| l.try_to::<ConsensusLog<NumberFor<Block>>>(id))
}
