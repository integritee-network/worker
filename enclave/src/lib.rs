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
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![crate_name = "substratee_worker_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

use env_logger;
use log::*;
use serde_json;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use base58::ToBase58;

use sgx_tunittest::*;
use sgx_types::{sgx_epid_group_id_t, sgx_status_t, sgx_target_info_t, size_t, SgxResult};

use substrate_api_client::{compose_extrinsic_offline, utils::storage_key_hash_vec};
use substratee_stf::{ShardIdentifier, Stf, TrustedCallSigned, TrustedGetterSigned};

use codec::{Decode, Encode};
use primitives::{crypto::Pair, hashing::blake2_256};

use constants::{CALL_CONFIRMED, RUNTIME_SPEC_VERSION, SUBSRATEE_REGISTRY_MODULE};
use std::slice;
use std::string::String;
use std::vec::Vec;

use std::collections::HashMap;
use substrate_api_client::utils::hexstr_to_u256;
use utils::{hash_from_slice, write_slice_and_whitespace_pad};

mod aes;
mod attestation;
mod constants;
mod ed25519;
mod io;
mod rsa3072;
mod state;
mod utils;

pub mod cert;
pub mod hex;
pub mod tls_ra;

pub const CERTEXPIRYDAYS: i64 = 90i64;

pub type Hash = primitives::H256;

#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
    // initialize the logging environment in the enclave
    env_logger::init();

    if let Err(status) = ed25519::create_sealed_if_absent() {
        return status;
    }

    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    info!(
        "[Enclave initialized] Ed25519 prim raw : {:?}",
        signer.public().0
    );

    if let Err(status) = rsa3072::create_sealed_if_absent() {
        return status;
    }

    // create the aes key that is used for state encryption such that a key is always present in tests.
    // It will be overwritten anyway if mutual remote attastation is performed with the primary worker
    if let Err(status) = aes::read_or_create_sealed() {
        return status;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
    pubkey: *mut u8,
    pubkey_size: u32,
) -> sgx_status_t {
    let rsa_pubkey = match rsa3072::unseal_pubkey() {
        Ok(key) => key,
        Err(status) => return status,
    };

    let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
        Ok(k) => k,
        Err(x) => {
            println!(
                "[Enclave] can't serialize rsa_pubkey {:?} {}",
                rsa_pubkey, x
            );
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
    write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
    if let Err(status) = ed25519::create_sealed_if_absent() {
        return status;
    }

    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    info!("Restored ECC pubkey: {:?}", signer.public());

    let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
    pubkey_slice.clone_from_slice(&signer.public());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn execute_stf(
    cyphertext: *const u8,
    cyphertext_size: u32,
    shard: *const u8,
    shard_size: u32,
    genesis_hash: *const u8,
    genesis_hash_size: u32,
    nonce: *const u32,
    node_url: *const u8,
    node_url_size: u32,
    unchecked_extrinsic: *mut u8,
    unchecked_extrinsic_size: u32,
) -> sgx_status_t {
    let cyphertext_slice = slice::from_raw_parts(cyphertext, cyphertext_size as usize);
    let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
    let genesis_hash = hash_from_slice(slice::from_raw_parts(
        genesis_hash,
        genesis_hash_size as usize,
    ));
    let node_url = slice::from_raw_parts(node_url, node_url_size as usize);
    let extrinsic_slice =
        slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

    debug!("load shielding keypair");
    let rsa_keypair = match rsa3072::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };

    // decrypt the payload
    debug!("decrypt the call");
    let request_vec = rsa3072::decrypt(&cyphertext_slice, &rsa_keypair);
    let stf_call_signed = TrustedCallSigned::decode(&mut request_vec.as_slice()).unwrap();

    debug!("query mrenclave of self");
    let mrenclave = match attestation::get_mrenclave_of_self() {
        Ok(m) => m,
        Err(status) => return status,
    };

    debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());
    if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
        error!("TrustedCallSigned: bad signature");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let mut state = match state::load(&shard) {
        Ok(s) => s,
        Err(status) => return status,
    };

    debug!("Update STF storage!");
    let requests = Stf::get_storage_hashes_to_update(&stf_call_signed.call)
        .into_iter()
        .map(|hash| WorkerRequest::ChainStorage(hash))
        .collect();

    let mut resp: Vec<WorkerResponse<Vec<u8>>> = match worker_request(requests, node_url) {
        Ok(r) => r,
        Err(status) => return status,
    };

    // Todo: after upgrade to api-client alpha branch we can directly store the encoded values into the HashMap and can be
    // agnostic to their actual types. Unfortunately, this is not possible with strings return by the api-client
    let (key, untrusted_nonce) = match resp.pop().unwrap() {
        WorkerResponse::ChainStorage(key, value, _proof) => (
            key,
            String::from_utf8(value)
                .map(|s| hexstr_to_u256(s).unwrap().low_u32())
                .unwrap(),
        ),
    };

    let mut update_map = HashMap::new();
    update_map.insert(key, untrusted_nonce.encode());
    Stf::update_storage(&mut state, update_map);

    debug!("execute STF");
    let mut calls_buffer = Vec::new();
    Stf::execute(
        &mut state,
        stf_call_signed.call,
        stf_call_signed.nonce,
        &mut calls_buffer,
    );

    let state_hash = match state::write(state, &shard) {
        Ok(h) => h,
        Err(status) => return status,
    };

    // get information for composing the extrinsic
    let signer = match ed25519::unseal_pair() {
        Ok(pair) => pair,
        Err(status) => return status,
    };
    debug!("Restored ECC pubkey: {:?}", signer.public());

    let call_hash = blake2_256(&request_vec);
    debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

    let mut nonce = *nonce.clone();

    let mut extrinsic_buffer: Vec<Vec<u8>> = calls_buffer
        .into_iter()
        .map(|call| {
            let xt = compose_extrinsic_offline!(
                signer.clone(),
                call,
                nonce.clone(),
                genesis_hash.clone(),
                RUNTIME_SPEC_VERSION
            )
            .encode();
            nonce += 1;
            xt
        })
        .collect();

    let xt_call = [SUBSRATEE_REGISTRY_MODULE, CALL_CONFIRMED];
    extrinsic_buffer.push(
        compose_extrinsic_offline!(
            signer,
            (xt_call, shard, call_hash.to_vec(), state_hash.encode()),
            nonce,
            genesis_hash,
            RUNTIME_SPEC_VERSION
        )
        .encode(),
    );

    write_slice_and_whitespace_pad(extrinsic_slice, extrinsic_buffer.encode());

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_state(
    trusted_op: *const u8,
    trusted_op_size: u32,
    shard: *const u8,
    shard_size: u32,
    value: *mut u8,
    value_size: u32,
) -> sgx_status_t {
    let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
    let mut trusted_op_slice = slice::from_raw_parts(trusted_op, trusted_op_size as usize);
    let value_slice = slice::from_raw_parts_mut(value, value_size as usize);
    let tusted_getter_signed = TrustedGetterSigned::decode(&mut trusted_op_slice).unwrap();

    debug!("verifying signature of TrustedCallSigned");
    if let false = tusted_getter_signed.verify_signature() {
        error!("bad signature");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    let mut state = match state::load(&shard) {
        Ok(s) => s,
        Err(status) => return status,
    };

    debug!("calling ito STF to get state");
    let value_opt = Stf::get_state(&mut state, tusted_getter_signed.getter);

    debug!("returning getter result");
    write_slice_and_whitespace_pad(value_slice, value_opt.encode());

    sgx_status_t::SGX_SUCCESS
}

extern "C" {
    pub fn ocall_read_ipfs(
        ret_val: *mut sgx_status_t,
        enc_state: *mut u8,
        enc_state_size: u32,
        cid: *const u8,
        cid_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_write_ipfs(
        ret_val: *mut sgx_status_t,
        enc_state: *const u8,
        enc_state_size: u32,
        cid: *mut u8,
        cid_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_worker_request(
        ret_val: *mut sgx_status_t,
        request: *const u8,
        req_size: u32,
        node_url: *const u8,
        node_url_size: u32,
        response: *mut u8,
        resp_size: u32,
    ) -> sgx_status_t;

    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
    rsgx_unit_tests!(
        // state::test_encrypted_state_io_works,
        test_ocall_read_write_ipfs,
        test_ocall_worker_request
    )
}

fn test_ocall_read_write_ipfs() {
    info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut cid_buf: Vec<u8> = vec![0; 46];
    let enc_state: Vec<u8> = vec![20; 36];

    let _res = unsafe {
        ocall_write_ipfs(
            &mut rt as *mut sgx_status_t,
            enc_state.as_ptr(),
            enc_state.len() as u32,
            cid_buf.as_mut_ptr(),
            cid_buf.len() as u32,
        )
    };

    let mut ret_state = vec![0; 36];
    let _res = unsafe {
        ocall_read_ipfs(
            &mut rt as *mut sgx_status_t,
            ret_state.as_mut_ptr(),
            ret_state.len() as u32,
            cid_buf.as_ptr(),
            cid_buf.len() as u32,
        )
    };

    assert_eq!(enc_state, ret_state);
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerRequest {
    ChainStorage(Vec<u8>), // (storage_key)
}

#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub enum WorkerResponse<V: Encode + Decode> {
    ChainStorage(Vec<u8>, V, Option<Vec<Vec<u8>>>), // (storage_key, storage_value, storage_proof)
}

fn worker_request<V: Encode + Decode>(
    req: Vec<WorkerRequest>,
    node_url: &[u8],
) -> SgxResult<Vec<WorkerResponse<V>>> {
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut resp: Vec<u8> = vec![0; 500];

    let res = unsafe {
        ocall_worker_request(
            &mut rt as *mut sgx_status_t,
            req.encode().as_ptr(),
            req.encode().len() as u32,
            node_url.as_ptr(),
            node_url.len() as u32,
            resp.as_mut_ptr(),
            resp.len() as u32,
        )
    };

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }
    Ok(Decode::decode(&mut resp.as_slice()).unwrap())
}

fn test_ocall_worker_request() {
    info!("testing ocall_worker_request. Hopefully substraTEE-node is running...");
    let mut requests = Vec::new();
    let node_url = format!("ws://{}:{}", "127.0.0.1", "9944").into_bytes();

    requests.push(WorkerRequest::ChainStorage(storage_key_hash_vec(
        "Balances",
        "TotalIssuance",
        None,
    )));

    let mut resp: Vec<WorkerResponse<Vec<u8>>> = match worker_request(requests, node_url.as_ref()) {
        Ok(response) => response,
        Err(_) => panic!("Worker response decode failed"),
    };

    let first = resp.pop().unwrap();
    info!("Worker response: {:?}", first);

    let total_issuance = match first {
        WorkerResponse::ChainStorage(_storage_key, value, _proof) => String::from_utf8(value)
            .map(|s| hexstr_to_u256(s).unwrap())
            .unwrap(),
    };

    info!("Total Issuance is: {:?}", total_issuance);
}
