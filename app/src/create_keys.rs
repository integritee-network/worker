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

extern crate sgx_types;

use sgx_types::*;
use constants::RSA3072_SEALED_KEY_FILE;
use enclave_api::*;

pub fn create_rsa3072_keypair(eid: sgx_enclave_id_t) -> () {
    println!("");
    println!("*** create RSA3072 keypair");

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let file = String::from(RSA3072_SEALED_KEY_FILE);

    let result = unsafe {
        create_sealed_rsa3072_keypair(
            eid,
            &mut retval,
            file.as_ptr() as *const u8,
            file.len())
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
}