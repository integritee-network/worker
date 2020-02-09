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

use sgx_types::*;

extern "C" {
    pub fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    pub fn execute_stf(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        cyphertext_encrypted: *mut u8,
        cyphertext_encrypted_size: u32,
        shard_encrypted: *mut u8,
        shard_encrypted_size: u32,
        hash: *const u8,
        hash_size: u32,
        nonce: *const u8,
        nonce_size: u32,
        unchecked_extrinsic: *mut u8,
        unchecked_extrinsic_size: u32,
    ) -> sgx_status_t;

    pub fn get_state(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        getter: *const u8,
        getter_size: u32,
        value: *mut u8,
        value_size: u32,
    ) -> sgx_status_t;

    pub fn get_rsa_encryption_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pubkey: *mut u8,
        pubkey_size: u32,
    ) -> sgx_status_t;

    pub fn get_ecc_signing_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pubkey: *mut u8,
        pubkey_size: u32,
    ) -> sgx_status_t;

    pub fn perform_ra(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        genesis_hash: *const u8,
        genesis_hash_size: u32,
        nonce: *const u8,
        nonce_size: u32,
        url: *const u8,
        url_size: u32,
        unchecked_extrinsic: *mut u8,
        unchecked_extrinsic_size: u32,
    ) -> sgx_status_t;

    pub fn dump_ra_to_disk(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    pub fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut size_t) -> sgx_status_t;
}
