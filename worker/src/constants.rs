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

pub static ENCRYPTED_STATE_FILE: &str = "state.bin";
pub static SHARDS_PATH: &str = "./shards";
pub static ENCLAVE_TOKEN: &str = "../bin/enclave.token";
pub static ENCLAVE_FILE: &str = "../bin/enclave.signed.so";
pub static SHIELDING_KEY_FILE: &str = "enclave-shielding-pubkey.json";
pub static SIGNING_KEY_FILE: &str = "enclave-signing-pubkey.bin";

#[cfg(feature = "production")]
pub static RA_SPID_FILE: &str = "../bin/spid_production.txt";
#[cfg(feature = "production")]
pub static RA_API_KEY_FILE: &str = "../bin/key_production.txt";

#[cfg(not(feature = "production"))]
pub static RA_SPID_FILE: &str = "../bin/spid.txt";
#[cfg(not(feature = "production"))]
pub static RA_API_KEY_FILE: &str = "../bin/key.txt";

// the maximum size of any extrinsic that the enclave will ever generate in B
pub static EXTRINSIC_MAX_SIZE: usize = 4196;
// the maximum size of a value that will be queried from the state in B
pub static STATE_VALUE_MAX_SIZE: usize = 1024;
