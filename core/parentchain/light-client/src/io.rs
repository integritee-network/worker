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
	light_client_init_params::LightClientInitParams,
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

pub fn read_or_init_validator<B, OCallApi>(
	params: LightClientInitParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		return init_validator::<B, OCallApi>(params, ocall_api)
	}

	let validation_state =
		LightClientStateSeal::<B, LightValidationState<B>>::unseal_from_static_file()?;

	let relay = validation_state
		.tracked_relays
		.get(&validation_state.num_relays)
		.ok_or(Error::NoSuchRelayExists)?;

	let genesis = relay.header_hashes[0];

	if genesis == params.get_genesis_header().hash() {
		let mut validator = init_validator::<B, OCallApi>(params, ocall_api)?;
		validator.set_state(validation_state);
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis);
		info!("light client state: {:?}", validator);
		Ok(validator)
	} else {
		init_validator::<B, OCallApi>(params, ocall_api)
	}
}

fn init_validator<B, OCallApi>(
	params: LightClientInitParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	B: Block,
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	// TODO: initialize relay will be more generic, so there will be changes here with issue #776
	let validator: LightValidation<B, OCallApi> = match params {
		LightClientInitParams::Grandpa { genesis_header, authorities, authority_proof } => {
			let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
				Arc::new(Box::new(GrandpaFinality {}));
			let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);
			validator.initialize_grandpa_relay(genesis_header, authorities, authority_proof)?;
			validator
		},
		LightClientInitParams::Parachain { genesis_header } => {
			let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> =
				Arc::new(Box::new(ParachainFinality {}));
			let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);
			validator.initialize_parachain_relay(genesis_header, AuthorityList::default())?;
			validator
		},
	};

	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;
	return Ok(validator)
}
