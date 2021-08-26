use crate::{error::Result, Error, Header, LightValidation, Validator};
use codec::{Decode, Encode};
use derive_more::Display;
use log::*;
use sp_finality_grandpa::VersionedAuthorityList;
use std::{fs, sgxfs::SgxFile};
use substratee_settings::files::CHAIN_RELAY_DB;
use substratee_sgx_io::{seal, unseal, SealedIO};
use substratee_storage::StorageProof;

#[derive(Copy, Clone, Debug, Display)]
pub struct LightClientSeal;

impl SealedIO for LightClientSeal {
	type Error = Error;
	type Unsealed = LightValidation;

	fn unseal() -> Result<Self::Unsealed> {
		Ok(unseal(CHAIN_RELAY_DB).map(|b| Decode::decode(&mut b.as_slice()))??)
	}

	fn seal(unsealed: Self::Unsealed) -> Result<()> {
		debug!("backup chain relay state");
		if fs::copy(CHAIN_RELAY_DB, format!("{}.1", CHAIN_RELAY_DB)).is_err() {
			warn!("could not backup previous chain relay state");
		};
		debug!("Seal Chain Relay State. Current state: {:?}", unsealed);

		Ok(unsealed.using_encoded(|bytes| seal(bytes, CHAIN_RELAY_DB))?)
	}
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

	let validator = LightClientSeal::unseal()?;

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

	validator.initialize_relay(header, auth.into(), proof)?;
	LightClientSeal::seal(validator.clone())?;

	Ok(validator.latest_finalized_header(validator.num_relays()).unwrap())
}
