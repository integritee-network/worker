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

use log::*;
/// keep this api free from chain-specific types!
use std::io::{Read, Write};
use std::{fs::File, path::PathBuf};

use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sgx_urts::SgxEnclave;

use crate::constants::{ENCLAVE_FILE, ENCLAVE_TOKEN, EXTRINSIC_MAX_SIZE, STATE_VALUE_MAX_SIZE};
use codec::{Decode, Encode};
use sp_core::ed25519;
use sp_finality_grandpa::VersionedAuthorityList;
use substratee_node_runtime::{Header, SignedBlock};

extern "C" {
    fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    fn get_state(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        cyphertext: *const u8,
        cyphertext_size: u32,
        shard: *const u8,
        shard_size: u32,
        value: *mut u8,
        value_size: u32,
    ) -> sgx_status_t;

    fn init_chain_relay(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        genesis_hash: *const u8,
        genesis_hash_size: usize,
        authority_list: *const u8,
        authority_list_size: usize,
        authority_proof: *const u8,
        authority_proof_size: usize,
        latest_header: *mut u8,
        latest_header_size: usize,
    ) -> sgx_status_t;

    fn sync_chain_relay(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        blocks: *const u8,
        blocks_size: usize,
        nonce: *const u32,
        unchecked_extrinsic: *mut u8,
        unchecked_extrinsic_size: usize,
    ) -> sgx_status_t;

    fn get_rsa_encryption_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pubkey: *mut u8,
        pubkey_size: u32,
    ) -> sgx_status_t;

    fn get_ecc_signing_pubkey(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        pubkey: *mut u8,
        pubkey_size: u32,
    ) -> sgx_status_t;

    fn get_mrenclave(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        mrenclave: *mut u8,
        mrenclave_size: u32,
    ) -> sgx_status_t;

    fn perform_ra(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        genesis_hash: *const u8,
        genesis_hash_size: u32,
        nonce: *const u32,
        w_url: *const u8,
        w_url_size: u32,
        unchecked_extrinsic: *mut u8,
        unchecked_extrinsic_size: u32,
    ) -> sgx_status_t;

    fn dump_ra_to_disk(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    fn test_main_entrance(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

pub fn enclave_init() -> SgxResult<SgxEnclave> {
    const LEN: usize = 1024;
    let mut launch_token = [0; LEN];
    let mut launch_token_updated = 0;

    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            info!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        }
        None => {
            error!("[-] Cannot get home dir");
            false
        }
    };
    let token_file = home_dir.join(ENCLAVE_TOKEN);
    if use_token {
        match File::open(&token_file) {
            Err(_) => {
                info!(
                    "[-] Token file {} not found! Will create one.",
                    token_file.as_path().to_str().unwrap()
                );
            }
            Ok(mut f) => {
                info!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(LEN) => {
                        info!("[+] Token file valid!");
                    }
                    _ => info!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: 1 = debug mode, 0 = not debug mode
    #[cfg(not(feature = "production"))]
    let debug = 1;
    #[cfg(feature = "production")]
    let debug = 0;

    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    let enclave = (SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    ))?;

    // Step 3: save the launch token if it is updated
    if use_token && launch_token_updated != 0 {
        // reopen the file with write capablity
        match File::create(&token_file) {
            Ok(mut f) => match f.write_all(&launch_token) {
                Ok(()) => info!("[+] Saved updated launch token!"),
                Err(_) => error!("[-] Failed to save updated launch token!"),
            },
            Err(_) => {
                warn!("[-] Failed to save updated enclave token, but doesn't matter");
            }
        }
    }

    let mut status = sgx_status_t::SGX_SUCCESS;
    // call the enclave's init fn
    let result = unsafe { init(enclave.geteid(), &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(enclave)
}

pub fn enclave_init_chain_relay(
    eid: sgx_enclave_id_t,
    genesis_header: Header,
    authority_list: VersionedAuthorityList,
    authority_proof: Vec<Vec<u8>>,
) -> SgxResult<Header> {
    let mut latest_header = vec![0u8; 200];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        // Todo: this is a bit ugly but the common `encode()` is not implemented for authority list
        authority_list.using_encoded(|authorities| {
            init_chain_relay(
                eid,
                &mut status,
                genesis_header.encode().as_ptr(),
                genesis_header.encode().len(),
                authorities.as_ptr(),
                authorities.len(),
                authority_proof.encode().as_ptr(),
                authority_proof.encode().len(),
                latest_header.as_mut_ptr(),
                latest_header.len(),
            )
        })
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    let latest: Header = Decode::decode(&mut latest_header.as_slice()).unwrap();
    info!("Latest Header {:?}", latest);

    Ok(latest)
}

pub fn enclave_sync_chain_relay(
    eid: sgx_enclave_id_t,
    blocks: Vec<SignedBlock>,
    tee_nonce: u32,
) -> SgxResult<Vec<u8>> {
    let mut status = sgx_status_t::SGX_SUCCESS;

    let mut unchecked_extrinsics: Vec<u8> = vec![0u8; EXTRINSIC_MAX_SIZE];

    let result = unsafe {
        blocks.using_encoded(|b| {
            sync_chain_relay(
                eid,
                &mut status,
                b.as_ptr(),
                b.len(),
                &tee_nonce,
                unchecked_extrinsics.as_mut_ptr(),
                EXTRINSIC_MAX_SIZE,
            )
        })
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    Ok(unchecked_extrinsics)
}

pub fn enclave_signing_key(eid: sgx_enclave_id_t) -> SgxResult<ed25519::Public> {
    let pubkey_size = 32;
    let mut pubkey = [0u8; 32];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result =
        unsafe { get_ecc_signing_pubkey(eid, &mut status, pubkey.as_mut_ptr(), pubkey_size) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    Ok(ed25519::Public::from_raw(pubkey))
}

pub fn enclave_shielding_key(eid: sgx_enclave_id_t) -> SgxResult<Rsa3072PubKey> {
    let pubkey_size = 8192;
    let mut pubkey = vec![0u8; pubkey_size as usize];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result =
        unsafe { get_rsa_encryption_pubkey(eid, &mut status, pubkey.as_mut_ptr(), pubkey_size) };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    let rsa_pubkey: Rsa3072PubKey = serde_json::from_slice(pubkey.as_slice()).unwrap();
    debug!("got RSA pubkey {:?}", rsa_pubkey);
    Ok(rsa_pubkey)
}

pub fn enclave_query_state(
    eid: sgx_enclave_id_t,
    cyphertext: Vec<u8>,
    shard: Vec<u8>,
) -> SgxResult<Vec<u8>> {
    let value_size = STATE_VALUE_MAX_SIZE;
    let mut value = vec![0u8; value_size as usize];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        get_state(
            eid,
            &mut status,
            cyphertext.as_ptr(),
            cyphertext.len() as u32,
            shard.as_ptr(),
            shard.len() as u32,
            value.as_mut_ptr(),
            value_size as u32,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    debug!("got state value: {:?}", hex::encode(value.clone()));
    Ok(value)
}

pub fn enclave_mrenclave(eid: sgx_enclave_id_t) -> SgxResult<[u8; 32]> {
    let mut m = [0u8; 32];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { get_mrenclave(eid, &mut status, m.as_mut_ptr(), m.len() as u32) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(m)
}

pub fn enclave_dump_ra(eid: sgx_enclave_id_t) -> SgxResult<()> {
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { dump_ra_to_disk(eid, &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(())
}

pub fn enclave_perform_ra(
    eid: sgx_enclave_id_t,
    genesis_hash: Vec<u8>,
    nonce: u32,
    w_url: Vec<u8>,
) -> SgxResult<Vec<u8>> {
    let unchecked_extrinsic_size = EXTRINSIC_MAX_SIZE;
    let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        perform_ra(
            eid,
            &mut status,
            genesis_hash.as_ptr(),
            genesis_hash.len() as u32,
            &nonce,
            w_url.as_ptr(),
            w_url.len() as u32,
            unchecked_extrinsic.as_mut_ptr(),
            unchecked_extrinsic_size as u32,
        )
    };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(unchecked_extrinsic)
}

pub fn enclave_test(eid: sgx_enclave_id_t) -> SgxResult<()> {
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { test_main_entrance(eid, &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(())
}
