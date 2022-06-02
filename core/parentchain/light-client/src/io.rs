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
	light_validation::LightValidation,
	Error, LightValidationState, NumberFor, Validator,
};
use alloc::sync::Arc;
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal, StaticSealedIO};
use itp_types::light_client_init_params::LightClientInitParams;
use log::*;
use sp_runtime::traits::Block;
use std::{boxed::Box, fs};

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

pub fn init_validator<B: Block, OCallApi: EnclaveOnChainOCallApi>(
	params: LightClientInitParams<B::Header>,
	ocall_api: Arc<OCallApi>,
) -> Result<LightValidation<B, OCallApi>>
where
	NumberFor<B>: finality_grandpa::BlockNumberOps,
{
	let genesis_header = params.get_genesis_header().clone();
	let authorities = params.get_authorities().cloned().unwrap_or_default();
	let authority_proof = params.get_authority_proof().cloned().unwrap_or_default();

	let finality: Arc<Box<dyn Finality<B> + Sync + Send + 'static>> = match params {
		LightClientInitParams::Grandpa { .. } => Arc::new(Box::new(GrandpaFinality {})),
		LightClientInitParams::Parachain { .. } => Arc::new(Box::new(ParachainFinality {})),
	};

	let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);

	validator.initialize_relay(genesis_header, authorities, authority_proof)?;
	LightClientStateSeal::<B, LightValidationState<B>>::seal_to_static_file(validator.get_state())?;

	return Ok(validator)
}
