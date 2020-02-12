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
use sgx_types::*;
use sgx_urts::SgxEnclave;

use codec::{Decode, Encode};

use crate::constants::{ENCLAVE_FILE, ENCLAVE_TOKEN};

extern "C" {
    fn init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;

    fn execute_stf(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        cyphertext_encrypted: *const u8,
        cyphertext_encrypted_size: u32,
        shard_encrypted: *const u8,
        shard_encrypted_size: u32,
        hash: *const u8,
        hash_size: u32,
        nonce: *const u8,
        nonce_size: u32,
        unchecked_extrinsic: *mut u8,
        unchecked_extrinsic_size: u32,
    ) -> sgx_status_t;

    fn get_state(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        getter: *const u8,
        getter_size: u32,
        value: *mut u8,
        value_size: u32,
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

    fn perform_ra(
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

pub fn enclave_signing_key(enclave: SgxEnclave) -> SgxResult<Vec<u8>> {
    let pubkey_size = 32;
    let mut pubkey = [0u8; 32];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        get_ecc_signing_pubkey(
            enclave.geteid(),
            &mut status,
            pubkey.as_mut_ptr(),
            pubkey_size,
        )
    };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(pubkey.encode())
}

pub fn enclave_shielding_key(enclave: SgxEnclave) -> SgxResult<Vec<u8>> {
    let pubkey_size = 8192;
    let mut pubkey = vec![0u8; pubkey_size as usize];

    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        get_rsa_encryption_pubkey(
            enclave.geteid(),
            &mut status,
            pubkey.as_mut_ptr(),
            pubkey_size,
        )
    };

    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }

    let rsa_pubkey: Rsa3072PubKey = serde_json::from_slice(&pubkey[..]).unwrap();
    debug!("got RSA pubkey {:?}", rsa_pubkey);
    Ok(pubkey)
}

pub fn enclave_dump_ra(enclave: SgxEnclave) -> SgxResult<()> {
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { dump_ra_to_disk(enclave.geteid(), &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(())
}

pub fn enclave_execute_stf(
    enclave: SgxEnclave,
    cyphertext: Vec<u8>,
    shard: Vec<u8>,
    genesis_hash: Vec<u8>,
    nonce: Vec<u8>,
) -> SgxResult<Vec<u8>> {
    let unchecked_extrinsic_size = 500;
    let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        execute_stf(
            enclave.geteid(),
            &mut status,
            cyphertext.as_ptr(),
            cyphertext.len() as u32,
            shard.as_ptr(),
            shard.len() as u32,
            genesis_hash.as_ptr(),
            genesis_hash.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
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

pub fn enclave_perform_ra(
    enclave: SgxEnclave,
    genesis_hash: Vec<u8>,
    nonce: Vec<u8>,
    url: Vec<u8>,
) -> SgxResult<Vec<u8>> {
    let unchecked_extrinsic_size = 500;
    let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        perform_ra(
            enclave.geteid(),
            &mut status,
            genesis_hash.as_ptr(),
            genesis_hash.len() as u32,
            nonce.as_ptr(),
            nonce.len() as u32,
            url.as_ptr(),
            url.len() as u32,
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

pub fn enclave_test(enclave: SgxEnclave) -> SgxResult<()> {
    let mut status = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { test_main_entrance(enclave.geteid(), &mut status) };
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(status);
    }
    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    Ok(())
}
