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

use crate::{error::Result, Error, LightClientState, LightValidation, NumberFor, Validator};
use codec::{Decode, Encode};
use derive_more::Display;
use itp_settings::files::LIGHT_CLIENT_DB;
use itp_sgx_io::{seal, unseal, StaticSealedIO};
use itp_storage::StorageProof;
use log::*;
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::traits::{Block, Header};
use std::{fs, sgxfs::SgxFile};

#[derive(Copy, Clone, Debug, Display)]
pub struct LightClientSeal<B> {
	_phantom: B,
}

impl<B: Block> StaticSealedIO for LightClientSeal<B> {
	type Error = Error;
	type Unsealed = LightValidation<B>;

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

pub fn read_or_init_validator<B: Block>(
	header: B::Header,
	auth: VersionedAuthorityList,
	proof: StorageProof,
) -> Result<B::Header>
where
	NumberFor<B>: finality_grandpa::BlockNumberOps,
{
	if SgxFile::open(LIGHT_CLIENT_DB).is_err() {
		info!("[Enclave] ChainRelay DB not found, creating new! {}", LIGHT_CLIENT_DB);
		return init_validator::<B>(header, auth, proof)
	}

	let validator = LightClientSeal::<B>::unseal_from_static_file()?;

	let genesis = validator.genesis_hash(validator.num_relays()).unwrap();
	if genesis == header.hash() {
		info!("Found already initialized light client with Genesis Hash: {:?}", genesis);
		info!("light client state: {:?}", validator);
		Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
	} else {
		init_validator::<B>(header, auth, proof)
	}
}

fn init_validator<B: Block>(
	header: B::Header,
	auth: VersionedAuthorityList,
	proof: StorageProof,
) -> Result<B::Header>
where
	NumberFor<B>: finality_grandpa::BlockNumberOps,
{
	let mut validator = LightValidation::<B>::new();

	validator.initialize_relay(header, auth.into(), proof)?;
	LightClientSeal::<B>::seal_to_static_file(validator.clone())?;

	Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
}
