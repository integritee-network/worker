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
	finality::{Finality, Grandpa, Parachain},
	light_validation::LightValidation,
	Error, LightClientState, NumberFor, Validator,
};
use alloc::sync::Arc;
use codec::{Decode, Encode};
use core::fmt::Debug;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal, StaticSealedIO};
use itp_types::light_client_init_params::LightClientInitParams;
use log::*;
use sgx_tstd::boxed::Box;
use sp_runtime::traits::{Block, Header};
use std::{fs, sgxfs::SgxFile};

#[derive(Copy, Clone, Debug)]
pub struct LightClientSeal<B, LightClient> {
	_phantom: (B, LightClient),
}

impl<B: Block, Client: Decode + Encode + Debug> StaticSealedIO for LightClientSeal<B, Client> {
	type Error = Error;
	type Unsealed = Client;

	fn unseal_from_static_file() -> Result<Self::Unsealed> {
		Ok(unseal(LIGHT_CLIENT_DB).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal_to_static_file(unsealed: Self::Unsealed) -> Result<()> {
		debug!("backup light client state");
		if fs::copy(LIGHT_CLIENT_DB, format!("{}.1", LIGHT_CLIENT_DB)).is_err() {
			warn!("could not backup previous light client state");
		};
		debug!("Seal light client State. Current state: {:?}", unsealed);
		Ok(unsealed.using_encoded(|bytes| seal(bytes, LIGHT_CLIENT_DB))?)
	}
}

pub fn read_or_init_validator<B: Block, OCallApi: EnclaveOnChainOCallApi>(
	params: LightClientInitParams<B::Header>,
	ocall_api: OCallApi,
) -> Result<B::Header>
where
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	LightValidation<B, OCallApi>: Decode + Encode + Debug,
{
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		return init_validator::<B, OCallApi>(params, ocall_api)
	}

	let validator = LightClientSeal::<B, LightValidation<B, OCallApi>>::unseal_from_static_file()?;

	let genesis = validator.genesis_hash(validator.num_relays()).unwrap();
	if genesis == params.get_genesis_header().hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis);
		info!("light client state: {:?}", validator);
		Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
	} else {
		init_validator::<B, OCallApi>(params, ocall_api)
	}
}

fn init_validator<B: Block, OCallApi: EnclaveOnChainOCallApi>(
	params: LightClientInitParams<B::Header>,
	ocall_api: OCallApi,
) -> Result<B::Header>
where
	NumberFor<B>: finality_grandpa::BlockNumberOps,
	LightValidation<B, OCallApi>: Decode + Encode + Debug,
{
	let genesis_header = params.get_genesis_header().clone();
	let authorities = params.get_authorities().unwrap().clone();
	let authority_proof = params.get_authority_proof().unwrap().clone();
	let finality: Arc<Box<dyn Finality<B>>> = match params {
		LightClientInitParams::Grandpa { authorities, authority_proof, .. } =>
			Arc::new(Box::new(Grandpa { authorities, authority_proof })),
		LightClientInitParams::Parachain { .. } => Arc::new(Box::new(Parachain {})),
	};

	let mut validator = LightValidation::<B, OCallApi>::new(ocall_api, finality);

	// TODO.
	validator.initialize_relay(genesis_header, authorities, authority_proof)?;
	LightClientSeal::<B, LightValidation<B, OCallApi>>::seal_to_static_file(validator.clone())?;

	return Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
}
