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

#![crate_name = "sealedkeyenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tseal;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

extern crate crypto;
extern crate rust_base58;
extern crate serde_json;
extern crate sgx_crypto_helper;

extern crate sgx_serialize;

// FIXME: don't work with no_std yet
//extern crate schnorrkel;
//use schnorrkel::keys::MiniSecretKey;
extern crate primitives;
use primitives::{ed25519, sr25519};
use primitives::crypto::UncheckedFrom;

//extern crate keyring;
extern crate my_node_runtime;
use my_node_runtime::{AccountId, UncheckedExtrinsic, CheckedExtrinsic, Call, BalancesCall, Hash, SubstraTEEProxyCall};
extern crate runtime_primitives;
use runtime_primitives::generic::Era;
extern crate parity_codec;
use parity_codec::{Encode, Compact};
extern crate primitive_types;
use primitive_types::U256;
//extern crate node_primitives;
//use node_primitives::Index;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};
use sgx_serialize::{SerializeHelper, DeSerializeHelper};
#[macro_use]
extern crate sgx_serialize_derive;
// use sgx_serialize::*;

use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
// use std::borrow::ToOwned;
use std::collections::HashMap;
use std::string::ToString;

use crypto::ed25519::{keypair, signature};
use rust_base58::{ToBase58};
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;

type Index = u64;

mod constants;
mod utils;
use constants::{RSA3072_SEALED_KEY_FILE, ED25519_SEALED_KEY_FILE, COUNTERSTATE};
/*
//FIXME: no_std broken here
/// Do a Blake2 256-bit hash and place result in `dest`.
pub fn blake2_256_into(data: &[u8], dest: &mut [u8; 32]) {
	dest.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
}
*/
/*
/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
	let mut r = [0; 32];
	blake2_256_into(data, &mut r);
	r
}
*/

#[no_mangle]
pub extern "C" fn get_rsa_encryption_pubkey(pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

	let mut retval = sgx_status_t::SGX_SUCCESS;
	match SgxFile::open(RSA3072_SEALED_KEY_FILE) {
		Err(x) => {
			println!("[Enclave] Keyfile not found, creating new! {}", x);
			retval = create_sealed_rsa3072_keypair();
		},
		_ => ()
	}

	if retval != sgx_status_t::SGX_SUCCESS {
		// detailed error msgs are already printed in utils::write file
		return retval;
	}

	//restore RSA key pair from file
	let mut keyvec: Vec<u8> = Vec::new();
	retval = utils::read_file(&mut keyvec, RSA3072_SEALED_KEY_FILE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
	//println!("[Enclave] key_json = {}", key_json_str);
	let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();

	// now write pubkey back to caller
	let pubkey_slice = unsafe { slice::from_raw_parts_mut(pubkey, pubkey_size as usize) };

	let keypair_json = match serde_json::to_string(&rsa_keypair) {
		Ok(k) => k,
		Err(x) => {
			println!("[Enclave] can't serialize rsa_keypair {:?} {}", rsa_keypair, x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED;
		}
	};
	println!("[Enclave] len pubkey_slice: {}", pubkey_slice.len());
	println!("[Enclave] len keypair_json: {}", keypair_json.len());

	let (left, right) = pubkey_slice.split_at_mut(keypair_json.len());
	left.clone_from_slice(keypair_json.as_bytes());
	right.iter_mut().for_each(|x| *x = 0x20);

	sgx_status_t::SGX_SUCCESS
}

fn create_sealed_rsa3072_keypair() -> sgx_status_t {
    let rsa_keypair = Rsa3072KeyPair::new().unwrap();
    let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
    // println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
	utils::write_file(rsa_key_json.as_bytes(), RSA3072_SEALED_KEY_FILE)
}

#[no_mangle]
pub extern "C" fn get_ecc_signing_pubkey(pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	match SgxFile::open(ED25519_SEALED_KEY_FILE) {
		Ok(_k) => (),
		Err(x) => {
			println!("[Enclave] Keyfile not found, creating new! {}", x);
			retval = create_sealed_ed25519_keypair();
		},
	}

	if retval != sgx_status_t::SGX_SUCCESS {
		// detailed error msgs are already printed in utils::write file
		return retval;
	}

	//restore ecc key pair from file
	let mut keyvec: Vec<u8> = Vec::new();
	retval = utils::read_file(&mut keyvec, ED25519_SEALED_KEY_FILE);
	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
	println!("[Enclave] key_json = {}", key_json_str);

	// Fixme: Here ends the wip

	sgx_status_t::SGX_SUCCESS
}

fn create_sealed_ed25519_keypair() -> sgx_status_t {
    let mut seed = [0u8; 32];
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut seed);

    // create ed25519 keypair
    let (_privkey, _pubkey) = keypair(&seed);
    println!("[Enclave] generated seed pubkey: {:?}", _pubkey.to_base58());

    let seed_json = serde_json::to_string(&seed).unwrap();
	utils::write_file(seed_json.as_bytes(), ED25519_SEALED_KEY_FILE)
}


#[no_mangle]
pub extern "C" fn call_counter(ciphertext: * mut u8,
											  ciphertext_size: u32,
											  unchechecked_extrinsic: * mut u8,
											  unchecked_extrinsic_size: u32) -> sgx_status_t {

    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_size as usize) };
    //restore RSA key pair from file
    let mut keyvec: Vec<u8> = Vec::new();
	let retval = utils::read_file(&mut keyvec, RSA3072_SEALED_KEY_FILE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
    //println!("[Enclave] key_json = {}", key_json_str);
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();

    let mut plaintext = Vec::new();
    rsa_keypair.decrypt_buffer(&ciphertext_slice, &mut plaintext).unwrap();

    let decrypted_string = String::from_utf8(plaintext).unwrap();
    println!("[Enclave] Decrypted data = {}", decrypted_string);

    let mut retval;
    let mut state_vec: Vec<u8> = Vec::new();

	retval = utils::read_counterstate(&mut state_vec, COUNTERSTATE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}
    // println!("state_vec = {:?}", &state_vec);

    // this is UGLY!!
    // todo: implement properly when interface is defined
    let v: Vec<_> = decrypted_string.split(',').collect();
    // println!("v = {:?}", v);
    // println!("v[0] = {}", v[0]);

    let number: Vec<u8> = v.iter().filter_map(|x| x.parse().ok()).collect();
    // println!("v[1] = {}", v[1]);
    // println!("number = {:?}", number);

    let helper = DeSerializeHelper::<AllCounts>::new(state_vec);
    let mut counter = helper.decode().unwrap();
    //FIXME: borrow checker trouble, -> should be fixed, untested
	increment_or_insert_counter(&mut counter, v[0], number[0]);
    retval = write_counter_state(counter);

	//FIXME: calculate hash, and pass genesis hash,
	let call_hash_str = "0x01234";
	let ex = compose_extrinsic(v[0], call_hash_str, U256([2,3,4,5]), call_hash_str);

	let encoded = ex.encode();
	let extrinsic_slize = unsafe { slice::from_raw_parts_mut(unchechecked_extrinsic, unchecked_extrinsic_size as usize) };
	extrinsic_slize.clone_from_slice(&encoded);
    retval
}

//untested function
#[no_mangle]
pub extern "C" fn get_counter(account: *const u8, account_size: u32, mut value: *mut u8) -> sgx_status_t {
	let mut state_vec: Vec<u8> = Vec::new();

	let account_slice = unsafe { slice::from_raw_parts(account, account_size as usize) };
	let acc_str = std::str::from_utf8(account_slice).unwrap();

	let retval = utils::read_counterstate(&mut state_vec, COUNTERSTATE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	let helper = DeSerializeHelper::<AllCounts>::new(state_vec);
	let mut counter = helper.decode().unwrap();
	value = counter.entries.entry(acc_str.to_string()).or_insert(0);

	retval
}

fn increment_or_insert_counter(counter: &mut AllCounts, name: &str, value: u8) {
	{
		let c = counter.entries.entry(name.to_string()).or_insert(0);
		*c += value;
	}
	if counter.entries.get(name).unwrap() == &value {
		println!("[Enclave] No counter found for '{}', adding new with initial value {}", name, value);
	} else {
		println!("[Enclave] Incremented counter for '{}'. New value: {:?}", name, counter.entries.get(name));
	}
}

fn write_counter_state(value: AllCounts) -> sgx_status_t {
    let helper = SerializeHelper::new();
    let c = helper.encode(value).unwrap();
	utils::write_file( &c, COUNTERSTATE)
}

#[no_mangle]
pub extern "C" fn sign(sealed_seed: * mut u8, sealed_seed_size: u32,
                        msg: * mut u8, msg_size: u32,
                        sig: * mut u8, sig_size: u32) -> sgx_status_t {

    // runseal seed
    let opt = from_sealed_log::<[u8; 32]>(sealed_seed, sealed_seed_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

    let seed = unsealed_data.get_decrypt_txt();

    //restore ed25519 keypair from seed
    let (_privkey, _pubkey) = keypair(seed);

    println!("[Enclave] restored sealed keyair with pubkey: {:?}", _pubkey.to_base58());

    // sign message
    let msg_slice = unsafe {
        slice::from_raw_parts_mut(msg, msg_size as usize)
    };
    let sig_slice = unsafe {
        slice::from_raw_parts_mut(sig, sig_size as usize)
    };
    let _sig = signature(&msg_slice, &_privkey);
    sig_slice.clone_from_slice(&_sig);

    sgx_status_t::SGX_SUCCESS
}

#[derive(Serializable, DeSerializable, Debug)]
struct AllCounts {
    entries: HashMap<String, u8>
}

fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
	unsafe {
		SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
	}
}

pub fn compose_extrinsic(sender: &str, call_hash_str: &str, index: U256, genesis_hash: &str) -> UncheckedExtrinsic {

    //FIXME: don't generate new keypair, use the one supplied as argument
    let mut seed = [0u8; 32];
    let mut rand = StdRng::new().unwrap();
    rand.fill_bytes(&mut seed);
    // create ed25519 keypair
    let (_privkey, _pubkey) = keypair(&seed);

    let era = Era::immortal();
	let function = Call::SubstraTEEProxy(SubstraTEEProxyCall::confirm_call(call_hash_str.as_bytes().to_vec()));

    let index = Index::from(index.low_u64());
    let raw_payload = (Compact(index), function, era, genesis_hash);

    let sign = raw_payload.using_encoded(|payload| if payload.len() > 256 {
        println!("unsupported payload size until blake hashing supports no_std");
        signature(&[0u8; 64], &_privkey)
    } else {
        //println!("signing {}", HexDisplay::from(&payload));
        signature(payload, &_privkey)
    });

    //FIXME: until node_runtime changes to ed25519, CheckedExtrinsic will expect a sr25519!
    // this should be correct
    let signerpub = ed25519::Public::unchecked_from(_pubkey);
    // this is fake
    let signerpub_fake = sr25519::Public::unchecked_from(_pubkey);

    //FIXME: true ed25519 signature is replaced by fake sr25519 signature here
    let signature_fake =  sr25519::Signature::default();

    UncheckedExtrinsic::new_signed(
        index,
        raw_payload.1,
        signerpub_fake.into(),
        signature_fake.into(),
        era,
    )
}
