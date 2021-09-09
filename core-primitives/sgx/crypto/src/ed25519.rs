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
use crate::error::{Error, Result};
use codec::Encode;
use derive_more::Display;
use itp_settings::files::SEALED_SIGNER_SEED_FILE;
use itp_sgx_io::{seal, unseal, SealedIO};
use log::*;
use sgx_rand::{Rng, StdRng};
use sp_core::{crypto::Pair, ed25519};
use std::{path::Path, sgxfs::SgxFile};

#[derive(Copy, Clone, Debug, Display)]
pub struct Ed25519Seal;

impl SealedIO for Ed25519Seal {
	type Error = Error;
	type Unsealed = ed25519::Pair;

	fn unseal() -> Result<ed25519::Pair> {
		let raw = unseal(SEALED_SIGNER_SEED_FILE)?;

		let key = ed25519::Pair::from_seed_slice(&raw)
			.map_err(|e| Error::Other(format!("{:?}", e).into()))?;

		Ok(key.into())
	}

	fn seal(unsealed: Self::Unsealed) -> Result<()> {
		Ok(unsealed.seed().using_encoded(|bytes| seal(bytes, SEALED_SIGNER_SEED_FILE))?)
	}
}

pub fn create_sealed_if_absent() -> Result<()> {
	if SgxFile::open(SEALED_SIGNER_SEED_FILE).is_err() {
		if Path::new(SEALED_SIGNER_SEED_FILE).exists() {
			panic!("[Enclave] Keyfile {} exists but can't be opened. has it been written by the same enclave?", SEALED_SIGNER_SEED_FILE);
		}
		info!("[Enclave] Keyfile not found, creating new! {}", SEALED_SIGNER_SEED_FILE);
		return create_sealed_seed()
	}
	Ok(())
}

pub fn create_sealed_seed() -> Result<()> {
	let mut seed = [0u8; 32];
	let mut rand = StdRng::new()?;
	rand.fill_bytes(&mut seed);

	Ok(seal(&seed, SEALED_SIGNER_SEED_FILE)?)
}
