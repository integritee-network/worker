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
use std::fs::File;
use std::io::{Read, Write};
use std::sgxfs::SgxFile;
use std::string::String;
use std::vec::Vec;

use sgx_types::*;

use crate::utils::UnwrapOrSgxErrorUnexpected;

pub fn unseal(filepath: &str) -> SgxResult<Vec<u8>> {
    SgxFile::open(filepath)
        .map(_read)
        .sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?
}

pub fn read(filepath: &str) -> SgxResult<Vec<u8>> {
    File::open(filepath)
        .map(_read)
        .sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?
}

fn _read<F: Read>(mut file: F) -> SgxResult<Vec<u8>> {
    let mut read_data: Vec<u8> = Vec::new();
    file.read_to_end(&mut read_data)
        .sgx_error_with_log("[Enclave] Reading File failed!")?;

    Ok(read_data)
}

pub fn read_to_string(filepath: &str) -> SgxResult<String> {
    let mut contents = String::new();
    File::open(filepath)
        .map(|mut f| f.read_to_string(&mut contents))
        .sgx_error_with_log(&format!("[Enclave] Could not read '{}'", filepath))?
        .sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?;

    Ok(contents)
}

pub fn seal(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
    SgxFile::create(filepath)
        .map(|f| _write(bytes, f))
        .sgx_error_with_log(&format!("[Enclave] Creating '{}' failed", filepath))?
}

pub fn write(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
    File::create(filepath)
        .map(|f| _write(bytes, f))
        .sgx_error_with_log(&format!("[Enclave] Creating '{}' failed", filepath))?
}

fn _write<F: Write>(bytes: &[u8], mut file: F) -> SgxResult<sgx_status_t> {
    file.write_all(bytes)
        .sgx_error_with_log("[Enclave] Writing File failed!")?;

    Ok(sgx_status_t::SGX_SUCCESS)
}

pub mod light_validation {
    use crate::constants::CHAIN_RELAY_DB;
    use crate::utils::UnwrapOrSgxErrorUnexpected;
    use chain_relay::storage_proof::StorageProof;
    use chain_relay::{Header, LightValidation};
    use codec::{Decode, Encode};
    use log::*;
    use sgx_types::{sgx_status_t, SgxResult};
    use sp_finality_grandpa::VersionedAuthorityList;
    use std::sgxfs::SgxFile;

    pub fn unseal() -> SgxResult<LightValidation> {
        let vec = super::unseal(CHAIN_RELAY_DB)?;
        LightValidation::decode(&mut vec.as_slice()).map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)
    }

    pub fn seal(validator: LightValidation) -> SgxResult<sgx_status_t> {
        debug!("Seal Chain Relay State. Current state: {:?}", validator);
        super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)
    }

    pub fn read_or_init_validator(
        header: Header,
        auth: VersionedAuthorityList,
        proof: StorageProof,
    ) -> SgxResult<Header> {
        if SgxFile::open(CHAIN_RELAY_DB).is_err() {
            info!(
                "[Enclave] ChainRelay DB not found, creating new! {}",
                CHAIN_RELAY_DB
            );
            return init_validator(header, auth, proof);
        }

        let validator = unseal().sgx_error_with_log("Error reading validator")?;

        let genesis = validator.genesis_hash(validator.num_relays).unwrap();
        if genesis == header.hash() {
            info!(
                "Found already initialized chain relay with Genesis Hash: {:?}",
                genesis
            );
            info!("Chain Relay state: {:?}", validator);
            Ok(validator.latest_header(validator.num_relays).unwrap())
        } else {
            init_validator(header, auth, proof)
        }
    }

    fn init_validator(
        header: Header,
        auth: VersionedAuthorityList,
        proof: StorageProof,
    ) -> SgxResult<Header> {
        let mut validator = LightValidation::new();

        validator
            .initialize_relay(header, auth.into(), proof)
            .sgx_error()?;
        super::seal(validator.encode().as_slice(), CHAIN_RELAY_DB)?;

        Ok(validator.latest_header(validator.num_relays).unwrap())
    }
}
