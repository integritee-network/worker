/*
	Copyright 2019 Supercomputing Systems AG

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
// Todo: remove when migration complete
pub use substratee_sgx_io::{read, read_to_string, seal, unseal, write};

pub mod light_validation {
	use crate::{error::Result, utils::UnwrapOrSgxErrorUnexpected};
	use chain_relay::{Header, LightValidation, Validator};
	use codec::{Decode, Encode};
	use log::*;
	use sp_finality_grandpa::VersionedAuthorityList;
	use std::{fs, sgxfs::SgxFile};
	use substratee_settings::files::CHAIN_RELAY_DB;
	use substratee_storage::StorageProof;

	pub fn unseal() -> Result<LightValidation> {
		let vec = super::unseal(CHAIN_RELAY_DB)?;
		Ok(LightValidation::decode(&mut vec.as_slice())?)
	}

	pub fn seal(validator: LightValidation) -> Result<()> {
		debug!("backup chain relay state");
		if fs::copy(CHAIN_RELAY_DB, format!("{}.1", CHAIN_RELAY_DB)).is_err() {
			warn!("could not backup previous chain relay state");
		};
		debug!("Seal Chain Relay State. Current state: {:?}", validator);
		Ok(super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)?)
	}

	pub fn read_or_init_validator(
		header: Header,
		auth: VersionedAuthorityList,
		proof: StorageProof,
	) -> Result<Header> {
		if SgxFile::open(CHAIN_RELAY_DB).is_err() {
			info!("[Enclave] ChainRelay DB not found, creating new! {}", CHAIN_RELAY_DB);
			return init_validator(header, auth, proof)
		}

		let validator = unseal().sgx_error_with_log("Error reading validator")?;

		let genesis = validator.genesis_hash(validator.num_relays()).unwrap();
		if genesis == header.hash() {
			info!("Found already initialized chain relay with Genesis Hash: {:?}", genesis);
			info!("Chain Relay state: {:?}", validator);
			Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
		} else {
			init_validator(header, auth, proof)
		}
	}

	fn init_validator(
		header: Header,
		auth: VersionedAuthorityList,
		proof: StorageProof,
	) -> Result<Header> {
		let mut validator = LightValidation::new();

		validator.initialize_relay(header, auth.into(), proof).sgx_error()?;
		super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)?;

		Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
	}
}
