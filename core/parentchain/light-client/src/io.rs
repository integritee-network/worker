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
	light_validation::LightValidation,
	Error, LightValidationState, NumberFor, Validator,
};
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal, StaticSealedIO};
use log::*;
use sp_finality_grandpa::AuthorityList;
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
	// FIXME: That should be an unique path.
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		return init_grandpa_validator::<B, OCallApi>(params, ocall_api)
	}

	let (validation_state, genesis_hash) = get_validation_state::<B>()?;

	let mut validator = init_grandpa_validator::<B, OCallApi>(params.clone(), ocall_api)?;

	if genesis_hash == params.genesis_header.hash() {
		validator.set_state(validation_state);
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
	}
	info!("light client state: {:?}", validator);
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
		return init_parachain_validator::<B, OCallApi>(params, ocall_api)
	}

	let (validation_state, genesis_hash) = get_validation_state::<B>()?;

	let mut validator = init_parachain_validator::<B, OCallApi>(params.clone(), ocall_api)?;

	if genesis_hash == params.genesis_header.hash() {
		validator.set_state(validation_state);
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis_hash);
	}
	info!("light client state: {:?}", validator);
	Ok(validator)
}

fn get_validation_state<B: Block>() -> Result<(LightValidationState<B>, B::Hash)>
where
	B: Block,
{
	let validation_state =
		LightClientStateSeal::<B, LightValidationState<B>>::unseal_from_static_file()?;

	let relay = validation_state
		.tracked_relays
		.get(&validation_state.num_relays)
		.ok_or(Error::NoSuchRelayExists)?;
	let genesis_hash = relay.header_hashes[0];

	Ok((validation_state, genesis_hash))
}

fn init_grandpa_validator<B, OCallApi>(
	params: GrandpaParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(GrandpaFinality {}));
	let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);
	validator.initialize_grandpa_relay(
		params.genesis_header,
		params.authorities,
		params.authority_proof,
	)?;

	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}

fn init_parachain_validator<B, OCallApi>(
	params: SimpleParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
		Arc::new(Box::new(ParachainFinality {}));
	let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);
	validator.initialize_parachain_relay(params.genesis_header, AuthorityList::default())?;

	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;
	Ok(validator)
}
