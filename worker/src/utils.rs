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

use log::*;
use primitives::{crypto::Pair, ed25519};
use runtime_primitives::MultiSignature;

use codec::{Decode, Encode};
use substratee_node_calls::{get_worker_amount, get_worker_info, AccountId, Enclave};

use crate::constants::*;

pub fn check_files() -> u8 {
    debug!("*** Check files");

    let mut missing_files = 0;
    missing_files += file_missing(ENCLAVE_FILE);
    missing_files += file_missing(RSA_PUB_KEY);
    missing_files += file_missing(ECC_PUB_KEY);

    // remote attestation files
    missing_files += file_missing(RA_SPID);
    missing_files += file_missing(RA_API_KEY);

    missing_files
}

fn file_missing(path: &str) -> u8 {
    if Path::new(path).exists() {
        debug!("File '{}' found", path);
        0
    } else {
        error!("File '{}' not found", path);
        1
    }
}

pub fn get_first_worker_that_is_not_equal_to_self<P: Pair>(
    api: &substrate_api_client::Api<P>,
    my_account: AccountId,
) -> Result<Enclave<AccountId, Vec<u8>>, &str>
where
    MultiSignature: From<P::Signature>,
{
    let w_amount = get_worker_amount(api);

    match w_amount {
        0 => error!("No worker registered. Can't get worker info from node!"),
        _ => {
            for i in 0..w_amount {
                let enc = get_worker_info(api, i);
                if my_account != enc.pubkey {
                    info!("[+] Found worker to fetch keys from!");
                    return Ok(enc);
                }
            }
        }
    }
    Err("No worker not equal to self found")
}

pub fn vec_to_ed25519_pub(vec: Vec<u8>) -> ed25519::Public {
    let mut raw: [u8; 32] = Default::default();
    raw.copy_from_slice(&vec);
    ed25519::Public::from_raw(raw)
}
