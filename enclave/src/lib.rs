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

extern crate base64;
extern crate bit_vec;
//extern crate blake2_no_std;
extern crate chrono;
//extern crate crypto;
extern crate env_logger;
extern crate httparse;
extern crate itertools;
extern crate lazy_static;
#[macro_use]
extern crate log;
//extern crate my_node_runtime;
extern crate num_bigint;
extern crate codec;
extern crate primitive_types;
extern crate primitives;
extern crate runtime_primitives;
extern crate rust_base58;
extern crate rustls;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate sgx_crypto_helper;
extern crate sgx_rand;
extern crate sgx_serialize;
#[macro_use]
extern crate sgx_serialize_derive;
extern crate sgx_tcrypto;
extern crate sgx_trts;
extern crate sgx_tse;
extern crate sgx_tseal;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tunittest;
extern crate sgx_types;
extern crate sgxwasm;
extern crate wasmi;
extern crate webpki;
extern crate webpki_roots;
extern crate yasna;
//extern crate ed25519_dalek;
#[macro_use]
extern crate substrate_api_client;
extern crate substratee_stf;


//use crypto::ed25519::{keypair, signature};
use substrate_api_client::{
	extrinsic::xt_primitives::{UncheckedExtrinsicV3, GenericAddress, GenericExtra, SignedPayload},
	crypto::AccountKey,
	extrinsic};

//use my_node_runtime::{Call, Hash, SubstraTEERegistryCall, UncheckedExtrinsic};
use codec::{Compact, Decode, Encode};
use primitive_types::U256;
use primitives::{ed25519, Pair, hashing::{blake2_256}};
use runtime_primitives::generic::Era;
use rust_base58::ToBase58;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use sgx_crypto_helper::RsaKeyPair;
use sgx_serialize::{DeSerializeHelper, SerializeHelper};
use sgx_tcrypto::rsgx_sha256_slice;
use sgx_tunittest::*;
use sgx_types::{sgx_sha256_hash_t, sgx_status_t, size_t};

use constants::{ED25519_SEALED_KEY_FILE, ENCRYPTED_STATE_FILE, RSA3072_SEALED_KEY_FILE};
use std::collections::HashMap;
use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::string::ToString;
use std::vec::Vec;

mod constants;
mod utils;
mod wasm;
mod attestation;

pub mod cert;
pub mod hex;
pub mod tls_ra;


pub const CERTEXPIRYDAYS: i64 = 90i64;

pub type Hash = primitives::H256;

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {

//  If this is called when already initialised, the enclave panics
//  initialize the logging environment in the enclaved
//	env_logger::init();

	if let Err(x) = SgxFile::open(RSA3072_SEALED_KEY_FILE) {
		info!("[Enclave] Keyfile not found, creating new! {}", x);
		if let Err(status) = create_sealed_rsa3072_keypair() {
			return status
		}
	}

	let rsa_pubkey = match utils::read_rsa_pubkey() {
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

	// split the pubkey_slice at the length of the rsa_pubkey_json
	// and fill the right side with whitespace so that the json can be decoded later on
	let (left, right) = pubkey_slice.split_at_mut(rsa_pubkey_json.len());
	left.clone_from_slice(rsa_pubkey_json.as_bytes());
	right.iter_mut().for_each(|x| *x = 0x20);

	sgx_status_t::SGX_SUCCESS
}

fn create_sealed_rsa3072_keypair() -> Result<sgx_status_t, sgx_status_t> {
	let rsa_keypair = Rsa3072KeyPair::new().unwrap();
	let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
	// println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
	utils::write_file(rsa_key_json.as_bytes(), RSA3072_SEALED_KEY_FILE)
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

	// initialize the logging environment in the enclave
	env_logger::init();

	match SgxFile::open(ED25519_SEALED_KEY_FILE) {
		Ok(_k) => (),
		Err(x) => {
			info!("[Enclave] Keyfile not found, creating new! {}", x);
			if let Err(status) = utils::create_sealed_ed25519_seed() {
				return status;
			}
		},
	}

	let seedvec = match utils::get_ecc_seed() {
		Ok(seed) => seed,
		Err(status) => return status,
	};
	let mut seed = [0u8; 32];
    let seedvec = &seedvec[..seed.len()]; // panics if not enough data
    seed.copy_from_slice(seedvec); 
	let signer = AccountKey::Ed(ed25519::Pair::from_seed(&seed));

	info!("[Enclave] Restored ECC pubkey: {:?}", signer.public().to_base58());

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer.public());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn call_counter_wasm(
	req_bin: *const u8,
	req_length: usize,
	ciphertext: *mut u8,
	ciphertext_size: u32,
	hash: *const u8,
	hash_size: u32,
	nonce: *const u8,
	nonce_size: u32,
	wasm_hash: *const u8,
	wasm_hash_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32
) -> sgx_status_t {

	let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_size as usize);
	let hash_slice       = slice::from_raw_parts(hash, hash_size as usize);
	let mut nonce_slice  = slice::from_raw_parts(nonce, nonce_size as usize);
	let extrinsic_slice  = slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	debug!("[Enclave] Read RSA keypair");
	let rsa_keypair = match utils::read_rsa_keypair() {
		Ok(pair) => pair,
		Err(status) => return status,
	};

	debug!("[Enclave] Read RSA keypair done");

	// decode the payload
	println!("    [Enclave] Decode the payload");
	let plaintext_vec = utils::decode_payload(&ciphertext_slice, &rsa_keypair);
	let plaintext_string = String::from_utf8(plaintext_vec.clone()).unwrap();
	let msg: Message = serde_json::from_str(&plaintext_string).unwrap();

	println!("    [Enclave] Message decoded:");
	println!("    [Enclave]   account   = {}", msg.account);
	println!("    [Enclave]   increment = {}", msg.amount);
	println!("    [Enclave]   sha256    = {:?}", msg.sha256);

	// get the calculated SHA256 hash
	let wasm_hash_slice = slice::from_raw_parts(wasm_hash, wasm_hash_size as usize);
	let wasm_hash_calculated: sgx_sha256_hash_t = serde_json::from_slice(wasm_hash_slice).unwrap();

	if let Err(status) = wasm::compare_hashes(wasm_hash_calculated, msg.sha256) {
		return status;
	}

	let state = match utils::read_state_from_file(ENCRYPTED_STATE_FILE) {
		Ok(state) => state,
		Err(status) => return status,
	};

	let mut counter: AllCounts = match state.len() {
		0 => AllCounts { entries: HashMap::new() },
		_ => {
			debug!("    [Enclave] State read, deserializing...");
			let helper = DeSerializeHelper::<AllCounts>::new(state);
			helper.decode().unwrap()
		}
	};

	// get the current counter value of the account or initialize with 0
	let counter_value_old: u32 = *counter.entries.entry(msg.account.to_string()).or_insert(0);
	info!("    [Enclave] Current counter state of '{}' = {}", msg.account, counter_value_old);

	println!("    [Enclave] Executing WASM code");
	let req_slice = slice::from_raw_parts(req_bin, req_length);
	let action_req: sgxwasm::SgxWasmAction = serde_json::from_slice(req_slice).unwrap();

	if let Err(status) = wasm::invoke_wasm_action(action_req, msg, &mut counter) {
		return status;
	}

	// write the counter state and return
	let enc_state = match encrypt_counter_state(counter) {
		Ok(s) => s,
		Err(sgx_status) => return sgx_status,
	};

	println!("    [Enclave] Updated encrypted state: {:?}", enc_state.to_vec());

	let state_hash = rsgx_sha256_slice(&enc_state).unwrap();

	if let Err(status) = utils::write_plaintext(&enc_state, ENCRYPTED_STATE_FILE) {
		return status
	}

	// get information for composing the extrinsic
	let seedvec = match utils::get_ecc_seed() {
		Ok(seed) => seed,
		Err(status) => return status,
	};
	let mut seed = [0u8; 32];
    let seedvec = &seedvec[..seed.len()]; // panics if not enough data
    seed.copy_from_slice(seedvec); 
	let signer = AccountKey::Ed(ed25519::Pair::from_seed(&seed));

	let nonce = U256::decode(&mut nonce_slice).unwrap();
	let index = nonce.low_u32();

	let genesis_hash = utils::hash_from_slice(hash_slice);
	//let call_hash = utils::blake2s(&plaintext_vec);
	let call_hash = blake2_256(&plaintext_vec);
	debug!("[Enclave]: Call hash {:?}", call_hash);

	//let ex = confirm_call_extrinsic(_seed, &call_hash, &state_hash, nonce, genesis_hash);
	let call = [7u8,3u8];

	let mut seed = [0u8; 32];
    let seedvec = &seedvec[..seed.len()]; // panics if not enough data
    seed.copy_from_slice(seedvec); 
	let signer = AccountKey::Ed(ed25519::Pair::from_seed(&seed));
	
	//FIXME: define constant at client
	let spec_version = 4;

	let xt = compose_extrinsic_offline!(
        signer,
	    (call, call_hash.to_vec(), state_hash.to_vec()),
	    index,
	    genesis_hash,
	    spec_version
    );	

	let encoded = xt.encode();

	// split the extrinsic_slice at the length of the encoded extrinsic
	// and fill the right side with whitespace
	let (left, right) = extrinsic_slice.split_at_mut(encoded.len());
	left.clone_from_slice(&encoded);
	right.iter_mut().for_each(|x| *x = 0x20);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_counter(account: *const u8, account_size: u32, value: *mut u32) -> sgx_status_t {
	let account_slice = slice::from_raw_parts(account, account_size as usize);
	let acc_str = std::str::from_utf8(account_slice).unwrap();

	let state = match utils::read_state_from_file(ENCRYPTED_STATE_FILE) {
		Ok(state) => state,
		Err(status) => return status,
	};

	let mut counter: AllCounts = match state.len() {
		0 => AllCounts { entries: HashMap::new() },
		_ => {
			debug!("    [Enclave] State read, deserializing...");
			let helper = DeSerializeHelper::<AllCounts>::new(state);
			helper.decode().unwrap()
		}
	};

	let ref_mut = &mut *value;
	*ref_mut = *counter.entries.entry(acc_str.to_string()).or_insert(0);
	sgx_status_t::SGX_SUCCESS
}

fn encrypt_counter_state(value: AllCounts) -> Result<Vec<u8>, sgx_status_t> {
	let helper = SerializeHelper::new();
	let mut c = helper.encode(value).unwrap();
	utils::aes_de_or_encrypt(&mut c)?;
	Ok(c)
}

#[derive(Serializable, DeSerializable, Debug)]
pub struct AllCounts {
	entries: HashMap<String, u32>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
	account: String,
	amount: u32,
	sha256: sgx_sha256_hash_t
}

type Call = [u8; 2];


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
		utils::test_encrypted_state_io_works,
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
