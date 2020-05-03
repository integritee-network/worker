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
use std::path::Path;
use std::sgxfs::SgxFile;
use std::vec::Vec;

use sgx_rand::{Rng, StdRng};
use sgx_types::*;

use log::*;
use sp_core::{crypto::Pair, ed25519};

use crate::constants::SEALED_SIGNER_SEED_FILE;
use crate::io;

pub fn unseal_pair() -> SgxResult<ed25519::Pair> {
    let seedvec = unseal_seed()?;

    let mut seed = [0u8; 32];
    let seedvec = &seedvec[..seed.len()];
    // panics if not enough data
    seed.copy_from_slice(seedvec);
    Ok(ed25519::Pair::from_seed(&seed))
}

pub fn create_sealed_if_absent() -> SgxResult<sgx_status_t> {
    if SgxFile::open(SEALED_SIGNER_SEED_FILE).is_err() {
        if Path::new(SEALED_SIGNER_SEED_FILE).exists() {
            panic!("[Enclave] Keyfile {} exists but can't be opened. has it been written by the same enclave?", SEALED_SIGNER_SEED_FILE);
        }
        info!(
            "[Enclave] Keyfile not found, creating new! {}",
            SEALED_SIGNER_SEED_FILE
        );
        return create_sealed_seed();
    }
    Ok(sgx_status_t::SGX_SUCCESS)
}

fn unseal_seed() -> SgxResult<Vec<u8>> {
    io::unseal(SEALED_SIGNER_SEED_FILE)
}

pub fn seal_seed(pair: &[u8]) -> SgxResult<sgx_status_t> {
    io::seal(pair, SEALED_SIGNER_SEED_FILE)
}

pub fn create_sealed_seed() -> SgxResult<sgx_status_t> {
    let mut seed = [0u8; 32];
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => {
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }
    };
    rand.fill_bytes(&mut seed);

    seal_seed(&seed)
}
