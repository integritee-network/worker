use std::sgxfs::SgxFile;
use std::vec::Vec;

use sgx_types::*;
use sgx_rand::{Rng, StdRng};

use primitives::{ed25519, crypto::Pair};
use log::*;

use crate::utils::*;
use crate::constants::SEALED_SIGNER_SEED_FILE;

pub fn get_sealed_ecc_pair() ->  SgxResult<ed25519::Pair> {
	let seedvec = get_ecc_seed()?;

	let mut seed = [0u8; 32];
	let seedvec = &seedvec[..seed.len()];
// panics if not enough data
	seed.copy_from_slice(seedvec);
	Ok(ed25519::Pair::from_seed(&seed))
}

pub fn create_sealed_ed25519_seed_if_not_existent() -> SgxResult<sgx_status_t> {
	if SgxFile::open(SEALED_SIGNER_SEED_FILE).is_err() {
		info ! ("[Enclave] Keyfile not found, creating new! {}", SEALED_SIGNER_SEED_FILE);
		return create_sealed_ed25519_seed()
	}
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn get_ecc_seed() -> SgxResult<Vec<u8>> {
	read_file(SEALED_SIGNER_SEED_FILE)
}

pub fn create_sealed_ed25519_seed() -> SgxResult<sgx_status_t> {
	let mut seed = [0u8; 32];
	let mut rand = match StdRng::new() {
		Ok(rng) => rng,
		Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};
	rand.fill_bytes(&mut seed);

	write_file(&seed, SEALED_SIGNER_SEED_FILE)
}
