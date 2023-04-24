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

use crate::{
	error::Result,
	finality::{Finality, GrandpaFinality, ParachainFinality},
	light_client_init_params::{GrandpaParams, SimpleParams},
	light_validation::{check_validator_set_proof, LightValidation},
	state::RelayState,
	LightClientDBPath, LightClientSealing, LightClientState, LightValidationState, NumberFor,
	Validator,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal};
use log::*;
use sp_runtime::traits::{Block, Header};
use std::{boxed::Box, fs, sgxfs::SgxFile, sync::Arc};

#[derive(Copy, Clone, Debug)]
pub struct LightClientStateSeal<B, LightClientState, DB> {
	_phantom: (B, LightClientState, DB),
}

pub struct LightClientDB;
impl LightClientDBPath for LightClientDB {
	fn path() -> &'static str {
		LIGHT_CLIENT_DB
	}
}

impl<B: Block, LightClientState: Decode + Encode + Debug, DB: LightClientDBPath>
	LightClientSealing<LightClientState> for LightClientStateSeal<B, LightClientState, DB>
{
	fn seal_to_static_file(unsealed: &LightClientState) -> Result<()> {
		debug!("backup light client state");
		if fs::copy(DB::path(), format!("{}.1", DB::path())).is_err() {
			warn!("could not backup previous light client state");
		};
		debug!("Seal light client State. Current state: {:?}", unsealed);
		Ok(unsealed.using_encoded(|bytes| seal(bytes, DB::path()))?)
	}

	fn unseal_from_static_file() -> Result<LightClientState> {
		Ok(unseal(DB::path()).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn exists() -> bool {
		SgxFile::open(DB::path()).is_err()
	}

	fn path() -> &'static str {
		DB::path()
	}
}

// FIXME: This is a lot of duplicate code for the initialization of two
// different but sameish light clients. Should be tackled with #1081
pub fn read_or_init_grandpa_validator<B, OCallApi, Seal>(
	params: GrandpaParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	Seal: LightClientSealing<LightValidationState<B>>,
{
	check_validator_set_proof::<B>(
		params.genesis_header.state_root(),
		params.authority_proof,
		&params.authorities,
	)?;

	if !Seal::exists() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", Seal::path());
		let validator = init_grandpa_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, params.authorities).into(),
		)?;
		Seal::seal_to_static_file(validator.get_state())?;
		return Ok(validator)
	}

	let validation_state = Seal::unseal_from_static_file()?;
	let genesis_hash = validation_state.genesis_hash()?;

	let init_state = if genesis_hash == params.genesis_header.hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
		validation_state
	} else {
		info!(
			"Previous light client db belongs to another parentchain genesis. Creating new: {:?}",
			genesis_hash
		);
		RelayState::new(params.genesis_header, params.authorities).into()
	};

	let validator = init_grandpa_validator::<B, OCallApi>(ocall_api, init_state)?;

	info!("light client state: {:?}", validator);

	Seal::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}

pub fn read_or_init_parachain_validator<B, OCallApi, Seal>(
	params: SimpleParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
	Seal: LightClientSealing<LightValidationState<B>>,
{
	// FIXME: That should be an unique path.
	if !Seal::exists() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", Seal::path());
		let validator = init_parachain_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, Default::default()).into(),
		)?;
		Seal::seal_to_static_file(validator.get_state())?;
		return Ok(validator)
	}

	let validation_state = Seal::unseal_from_static_file()?;
	let genesis_hash = validation_state.genesis_hash()?;

	let init_state = if genesis_hash == params.genesis_header.hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
		validation_state
	} else {
		info!(
			"Previous light client db belongs to another parentchain genesis. Creating new: {:?}",
			genesis_hash
		);
		RelayState::new(params.genesis_header, vec![]).into()
	};

	let validator = init_parachain_validator::<B, OCallApi>(ocall_api, init_state)?;
	info!("light client state: {:?}", validator);

	Seal::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}

fn init_grandpa_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(GrandpaFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state);

	Ok(validator)
}

fn init_parachain_validator<B, OCallApi>(
	ocall_api: Arc<OCallApi>,
	state: LightValidationState<B>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(ParachainFinality));

	let validator = LightValidation::<B, OCallApi>::new(ocall_api, finality, state);
	Ok(validator)
}
