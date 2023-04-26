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
	Error, LightValidationState, NumberFor, Validator,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal, StaticSealedIO};
use log::*;
use sp_runtime::traits::{Block, Header};
use std::{boxed::Box, fs, sgxfs::SgxFile, sync::Arc};

#[derive(Copy, Clone, Debug)]
pub struct LightClientStateSeal<B, LightClientState> {
	_phantom: (B, LightClientState),
}

impl<B: Block, LightClientState: Decode + Encode + Debug> StaticSealedIO
	for LightClientStateSeal<B, LightClientState>
{
	type Error = Error;
	type Unsealed = LightClientState;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(unseal(LIGHT_CLIENT_DB).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal_to_static_file(unsealed: &Self::Unsealed) -> Result<()> {
		debug!("backup light client state");
		if fs::copy(LIGHT_CLIENT_DB, format!("{}.1", LIGHT_CLIENT_DB)).is_err() {
			warn!("could not backup previous light client state");
		};
		debug!("Seal light client State. Current state: {:?}", unsealed);
		Ok(unsealed.using_encoded(|bytes| seal(bytes, LIGHT_CLIENT_DB))?)
	}
}

// FIXME: This is a lot of duplicate code for the initialization of two
// different but sameish light clients. Should be tackled with #1081
pub fn read_or_init_grandpa_validator<B, OCallApi>(
	params: GrandpaParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	check_validator_set_proof::<B>(
		params.genesis_header.state_root(),
		params.authority_proof,
		&params.authorities,
	)?;

	// FIXME: That should be an unique path.
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		let validator = init_grandpa_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, params.authorities).into(),
		)?;
		LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(
			validator.get_state(),
		)?;
		return Ok(validator)
	}

	let (validation_state, genesis_hash) = get_validation_state::<B>()?;

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

	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}

pub fn read_or_init_parachain_validator<B, OCallApi>(
	params: SimpleParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	// FIXME: That should be an unique path.
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		let validator = init_parachain_validator::<B, OCallApi>(
			ocall_api,
			RelayState::new(params.genesis_header, Default::default()).into(),
		)?;
		LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(
			validator.get_state(),
		)?;
		return Ok(validator)
	}

	let (validation_state, genesis_hash) = get_validation_state::<B>()?;

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

	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}

// Todo: Implement this on the `LightClientStateSeal` itself.
fn get_validation_state<B: Block>() -> Result<(LightValidationState<B>, B::Hash)> {
	let validation_state =
		LightClientStateSeal::<B, LightValidationState<B>>::unseal_from_static_file()?;

	let relay = validation_state.get_relay();
	let genesis_hash = relay.header_hashes[0];

	Ok((validation_state, genesis_hash))
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
