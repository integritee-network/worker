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

use codec::Encode;
use keyring::AccountKeyring;
use primitive_types::U256;
use primitives::hash::H256;
use sgx_types::*;
use sgx_urts::SgxEnclave;
use substratee_stf;
use crate::constants::EXTRINSIC_MAX_SIZE;
use crate::enclave::api::*;
use crate::tests::commons::*;

// TODO: test get_ecc_signing_pubkey
// TODO: test get_rsa_encryption_pubkey

/* who needs get_state anyway?
pub fn get_state_works(eid: sgx_enclave_id_t) {
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let value_size = 16; //u128
    let mut value: Vec<u8> = vec![0u8; value_size as usize];

    let alice = AccountKeyring::Alice;
    let trusted_getter_signed = test_trusted_getter_signed(alice).encode();

    let result = unsafe {
        get_state(
            eid,
            &mut retval,
            trusted_getter_signed.as_ptr(),
            trusted_getter_signed.len() as u32,
            value.as_mut_ptr(),
            value_size as u32,
        )
    };
    println!("{} value: {:?}", alice, value);
    evaluate_result(retval);
    evaluate_result(result);
}
*/

pub fn execute_stf_works(eid: sgx_enclave_id_t) {
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let mut cyphertext = encrypted_test_msg(eid.clone());

    let unchecked_extrinsic_size = EXTRINSIC_MAX_SIZE;
    let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
    let nonce = 0u32;
    let genesis_hash: [u8; 32] = [0; 32];
    let shard = H256::default();

    let uxt = enclave_execute_stf(
        eid,
        cyphertext,
        shard.encode(),
        genesis_hash.encode(),
        nonce,
    )
    .unwrap();
}
