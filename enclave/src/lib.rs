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

use sgx_tcrypto::rsgx_sha256_slice;
use sgx_tunittest::*;
use sgx_types::{sgx_status_t, size_t};

use substratee_stf::{Stf, TrustedCall, TrustedGetter, State};
use sgx_externalities::SgxExternalitiesTrait;
use substrate_api_client::compose_extrinsic_offline;

use codec::{Decode, Encode};
use primitives::{crypto::Pair, hashing::{blake2_256}};

use constants::{
	ENCRYPTED_STATE_FILE,
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
	info!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer.public());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn execute_stf(
	request_encrypted: *mut u8,
	request_encrypted_size: u32,
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u8,
	nonce_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32
) -> sgx_status_t {

	let request_encrypted_slice = slice::from_raw_parts(request_encrypted, request_encrypted_size as usize);
	let genesis_hash_slice      = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	let mut nonce_slice  = slice::from_raw_parts(nonce, nonce_size as usize);
	let extrinsic_slice  = slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	debug!("[Enclave] Read RSA keypair");
	let rsa_keypair = match rsa3072::unseal_pair() {
		Ok(pair) => pair,
		Err(status) => return status,
	};

	debug!("[Enclave] Read RSA keypair done");

	// decrypt the payload
	debug!("    [Enclave] Decode the payload");
	let request_vec = rsa3072::decrypt(&request_encrypted_slice, &rsa_keypair);
	let stf_call = TrustedCall::decode(&mut request_vec.as_slice()).unwrap();

	// load last state
	let state_enc = match state::read(ENCRYPTED_STATE_FILE) {
		Ok(state) => state,
		Err(status) => return status,
	};

	let mut state : State = match state_enc.len() {
		0 => Stf::init_state(),
		_ => {
			debug!("    [Enclave] State read, deserializing...");
			State::decode(state_enc)
		}
	};

	debug!("    [Enclave] executing STF...");
	Stf::execute(&mut state, stf_call);

	// write the counter state and return
	let enc_state = match state::encrypt(state.encode()) {
		Ok(s) => s,
		Err(sgx_status) => return sgx_status,
	};


	let state_hash = rsgx_sha256_slice(&enc_state).unwrap();
	debug!("    [Enclave] Updated encrypted state. hash=0x{}", hex::encode_hex(&state_hash));

	if let Err(status) = io::write(&enc_state, ENCRYPTED_STATE_FILE) {
		return status
	}

	// get information for composing the extrinsic
	let signer = match ed25519::unseal_pair() {
		Ok(pair) => pair,
		Err(status) => return status,
	};
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let nonce = u32::decode(&mut nonce_slice).unwrap();
	debug!("using nonce for confirmation extrinsic: {:?}", nonce);
	let genesis_hash = hash_from_slice(genesis_hash_slice);
	let call_hash = blake2_256(&request_vec);
	debug!("[Enclave]: Call hash 0x{}", hex::encode_hex(&call_hash));

	let xt_call = [SUBSRATEE_REGISTRY_MODULE, CALL_CONFIRMED];

	let xt = compose_extrinsic_offline!(
        signer,
	    (xt_call, call_hash.to_vec(), state_hash.to_vec()),
	    nonce,
	    genesis_hash,
	    RUNTIME_SPEC_VERSION
    );

	let encoded = xt.encode();
	write_slice_and_whitespace_pad(extrinsic_slice, encoded);

	sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub unsafe extern "C" fn get_state(
	getter: *const u8,
	getter_size: u32,
	value: *mut u8,
	value_size: u32
	) -> sgx_status_t {

	let mut getter_slice = slice::from_raw_parts(getter, getter_size as usize);
	let value_slice  = slice::from_raw_parts_mut(value, value_size as usize);

	// load last state
	let state_vec = match state::read(ENCRYPTED_STATE_FILE) {
		Ok(state) => state,
		Err(status) => return status,
	};

	let mut state : State = match state_vec.len() {
		0 => Stf::init_state(),
		_ => {
			debug!("    [Enclave] State read, deserializing...");
			State::decode(state_vec)
		}
	};
	let _getter = TrustedGetter::decode(&mut getter_slice).unwrap();
	let value_vec = match Stf::get_state(&mut state, _getter) {
		Some(val) => val,
		None => vec!(0),
	};

//	//FIXME: now implicitly assuming we pass unsigned integer vecs, not strings terminated by 0x20
//	//FIXME: we should really pass an Option<Vec<u8>>
	write_slice_and_whitespace_pad(value_slice, value_vec);

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
