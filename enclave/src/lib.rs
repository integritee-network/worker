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

use env_logger;
use log::*;
use serde_json;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use base58::{FromBase58, ToBase58};


use sgx_tunittest::*;
use sgx_types::{sgx_status_t, size_t, sgx_target_info_t, sgx_epid_group_id_t, SgxResult };

use substratee_stf::{Stf, State as StfState, TrustedGetterSigned, TrustedCallSigned, ShardIdentifier};
use sgx_externalities::SgxExternalitiesTrait;
use substrate_api_client::compose_extrinsic_offline;

use codec::{Decode, Encode};
use primitives::{crypto::Pair, hashing::{blake2_256}, H256};

use constants::{
	ENCRYPTED_STATE_FILE,
	SHARDS_PATH,
	SUBSRATEE_REGISTRY_MODULE,
	CALL_CONFIRMED,
	RUNTIME_SPEC_VERSION,
};
use std::slice;
use std::string::String;
use std::vec::Vec;

use utils::{hash_from_slice, write_slice_and_whitespace_pad};

mod constants;
mod utils;
mod attestation;
mod rsa3072;
mod ed25519;
mod state;
mod aes;
mod io;

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
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	if let Err(status) = rsa3072::create_sealed_if_absent() {
		return status;
	}
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {

	let rsa_pubkey = match rsa3072::unseal_pubkey() {
		Ok(key) => key,
		Err(status) => return status,
	};

	let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
		Ok(k) => k,
		Err(x) => {
			println!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED;
		}
	};

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

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
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32
) -> sgx_status_t {

	let cyphertext_slice = slice::from_raw_parts(cyphertext, cyphertext_size as usize);
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let genesis_hash = hash_from_slice(slice::from_raw_parts(genesis_hash, genesis_hash_size as usize));
	let extrinsic_slice  = slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

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

	debug!("execute STF");
	Stf::execute(&mut state, stf_call_signed.call, stf_call_signed.nonce);

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

	
	debug!("confirmation extrinsic nonce: {:?}", nonce);
	let call_hash = blake2_256(&request_vec);
	debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

	let xt_call = [SUBSRATEE_REGISTRY_MODULE, CALL_CONFIRMED];

	let xt = compose_extrinsic_offline!(
        signer,
	    (xt_call, shard, call_hash.to_vec(), state_hash.encode()),
	    *nonce,
	    genesis_hash,
	    RUNTIME_SPEC_VERSION
    );

	let encoded = xt.encode();
	write_slice_and_whitespace_pad(extrinsic_slice, encoded);

	sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub unsafe extern "C" fn get_state(
	trusted_op: *const u8,
	trusted_op_size: u32,
	shard: *const u8,
	shard_size: u32,	
	value: *mut u8,
	value_size: u32
) -> sgx_status_t {
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let mut trusted_op_slice = slice::from_raw_parts(trusted_op, trusted_op_size as usize);
	let mut value_slice  = slice::from_raw_parts_mut(value, value_size as usize);
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
		ret_val			: *mut sgx_status_t,
		enc_state		: *mut u8,
		enc_state_size	: u32,
		cid				: *const u8,
		cid_size		: u32,
	) -> sgx_status_t;
}

extern "C" {
	pub fn ocall_write_ipfs(
		ret_val			: *mut sgx_status_t,
		enc_state		: *const u8,
		enc_state_size	: u32,
		cid				: *mut u8,
		cid_size		: u32,
	) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	rsgx_unit_tests!(
		state::test_encrypted_state_io_works,
		test_ocall_read_write_ipfs
		)
}

fn test_ocall_read_write_ipfs() {
	info!("testing IPFS read/write. Hopefully ipfs daemon is running...");
	let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
	let mut cid_buf: Vec<u8> = vec![0; 46];
	let enc_state: Vec<u8> = vec![20; 36];

	let _res = unsafe {
		ocall_write_ipfs(&mut rt as *mut sgx_status_t,
						 enc_state.as_ptr(),
						 enc_state.len() as u32,
						 cid_buf.as_mut_ptr(),
						 cid_buf.len() as u32)
	};

	let mut ret_state= vec![0; 36];
	let _res = unsafe {
		ocall_read_ipfs(&mut rt as *mut sgx_status_t,
						ret_state.as_mut_ptr(),
						ret_state.len() as u32,
						cid_buf.as_ptr(),
		cid_buf.len() as u32)
	};

	assert_eq!(enc_state, ret_state);
}

extern "C" {
	pub fn ocall_sgx_init_quote (
		ret_val : *mut sgx_status_t,
		ret_ti  : *mut sgx_target_info_t,
		ret_gid : *mut sgx_epid_group_id_t) -> sgx_status_t;
}