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

pub const RSA3072_SEALED_KEY_FILE: &str = "rsa3072_key_sealed.bin";
pub const SEALED_SIGNER_SEED_FILE: &str = "ed25519_key_sealed.bin";
pub const ENCRYPTED_STATE_FILE: &str = "state.bin";
pub const SHARDS_PATH: &str = "./shards";
pub const AES_KEY_FILE_AND_INIT_V: &str = "aes_key_sealed.bin";
pub const CHAIN_RELAY_DB: &str = "chain_relay_db.bin";

pub const RA_DUMP_CERT_DER_FILE: &str = "ra_dump_cert.der";

#[cfg(feature = "production")]
pub static RA_SPID_FILE: &str = "../bin/spid_production.txt";
#[cfg(feature = "production")]
pub static RA_API_KEY_FILE: &str = "../bin/key_production.txt";

#[cfg(not(feature = "production"))]
pub static RA_SPID_FILE: &str = "../bin/spid.txt";
#[cfg(not(feature = "production"))]
pub static RA_API_KEY_FILE: &str = "../bin/key.txt";

// you may have to update these indices upon new builds of the runtime
// you can get the index from metadata
// when counting modules, make sure to only count those that have calls.
pub static SUBSRATEE_REGISTRY_MODULE: u8 = 6u8;
pub static REGISTER_ENCLAVE: u8 = 0u8;
//pub static UNREGISTER_ENCLAVE: u8 = 1u8;
pub static CALL_WORKER: u8 = 2u8;
pub static CALL_CONFIRMED: u8 = 3u8;
pub static SHIELD_FUNDS: u8 = 4u8;

// bump this to be consistent with SubstraTEE-node runtime
pub static RUNTIME_SPEC_VERSION: u32 = 1;
