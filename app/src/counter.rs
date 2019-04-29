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
use enclave_api::*;

pub fn count(eid: sgx_enclave_id_t, account: &str) {
    // let enclave = match init_enclave() {
    //     Ok(r) => {
    //         println!("[+] Init Enclave Successful {}!", r.geteid());
    //         r
    //     },
    //     Err(x) => {
    //         println!("[-] Init Enclave Failed {}!", x.as_str());
    //         return;
    //     },
    // };

    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        increment_counter(eid,
        &mut retval,
        account,
        account.len() as u32
        )
    };

    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    // enclave.destroy();
}