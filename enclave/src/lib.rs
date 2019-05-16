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

extern crate log;

extern crate primitives;
use primitives::{ed25519};

extern crate wasmi;
extern crate sgxwasm;

extern crate my_node_runtime;
use my_node_runtime::{UncheckedExtrinsic, Call, Hash, SubstraTEEProxyCall};
extern crate runtime_primitives;
use runtime_primitives::generic::Era;
extern crate parity_codec;
use parity_codec::{Decode, Encode, Compact};
extern crate primitive_types;
use primitive_types::U256;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};
use sgx_serialize::{SerializeHelper, DeSerializeHelper};
#[macro_use]
extern crate sgx_serialize_derive;

#[macro_use]
extern crate lazy_static;

use log::*;
use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::collections::HashMap;
use std::string::ToString;
use std::sync::SgxMutex;

use crypto::ed25519::{keypair, signature};
use rust_base58::{ToBase58};
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair};

use sgxwasm::{SpecDriver, boundary_value_to_runtime_value, result_covert};

type Index = u64;

mod constants;
mod utils;
use constants::{RSA3072_SEALED_KEY_FILE, ED25519_SEALED_KEY_FILE, COUNTERSTATE};

lazy_static!{
    static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
}

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
    let mut sd = SPECDRIVER.lock().unwrap();
    *sd = SpecDriver::new();
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_rsa_encryption_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {

	let mut retval = sgx_status_t::SGX_SUCCESS;
	match SgxFile::open(RSA3072_SEALED_KEY_FILE) {
		Err(x) => {
			info!("[Enclave] Keyfile not found, creating new! {}", x);
			retval = create_sealed_rsa3072_keypair();
		},
		_ => ()
	}

	if retval != sgx_status_t::SGX_SUCCESS {
		// detailed error msgs are already printed in utils::write file
		return retval;
	}

	let rsa_keypair = utils::read_rsa_keypair(&mut retval);
    let rsa_pubkey = rsa_keypair.export_pubkey().unwrap();
    // println!("rsa_pubkey = {:?}", rsa_pubkey);

    let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
		Ok(k) => k,
		Err(x) => {
			println!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED;
		}
	};

	let pubkey_slice = unsafe { slice::from_raw_parts_mut(pubkey, pubkey_size as usize) };

    // split the pubkey_slice at the length of the rsa_pubkey_json
    // and fill the right side with whitespace so that the json can be decoded later on
	let (left, right) = pubkey_slice.split_at_mut(rsa_pubkey_json.len());
	left.clone_from_slice(rsa_pubkey_json.as_bytes());
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
			info!("[Enclave] Keyfile not found, creating new! {}", x);
			retval = create_sealed_ed25519_seed();
		},
	}

	if retval != sgx_status_t::SGX_SUCCESS {
		// detailed error msgs are already printed in utils::write file
		return retval;
	}

	let _seed = _get_ecc_seed_file(&mut retval);
	let (_privkey, _pubkey) = keypair(&_seed);
	info!("[Enclave] Restored ECC pubkey: {:?}", _pubkey.to_base58());

	let pubkey_slice = unsafe { slice::from_raw_parts_mut(pubkey, pubkey_size as usize) };
	pubkey_slice.clone_from_slice(&_pubkey);

	sgx_status_t::SGX_SUCCESS
}

fn _get_ecc_seed_file(status: &mut sgx_status_t) -> (Vec<u8>) {
	let mut seed_vec: Vec<u8> = Vec::new();
	*status = utils::read_file(&mut seed_vec, ED25519_SEALED_KEY_FILE);
	seed_vec
}

fn create_sealed_ed25519_seed() -> sgx_status_t {
    let mut seed = [0u8; 32];
    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut seed);

	utils::write_file(&seed, ED25519_SEALED_KEY_FILE)
}

#[no_mangle]
pub extern "C" fn call_counter(ciphertext: * mut u8,
							   ciphertext_size: u32,
							   hash: * const u8,
							   hash_size: u32,
							   nonce: * const u8,
							   nonce_size: u32,
							   unchechecked_extrinsic: * mut u8,
							   unchecked_extrinsic_size: u32) -> sgx_status_t {

    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_size as usize) };
	let hash_slice = unsafe { slice::from_raw_parts(hash, hash_size as usize) };
	let mut nonce_slice = unsafe {slice::from_raw_parts(nonce, nonce_size as usize)};
	let extrinsic_slize = unsafe { slice::from_raw_parts_mut(unchechecked_extrinsic, unchecked_extrinsic_size as usize) };

	let mut retval = sgx_status_t::SGX_SUCCESS;

	let rsa_keypair = utils::read_rsa_keypair(&mut retval);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	// decode the message
	let plaintext = utils::get_plaintext_from_encrypted_data(&ciphertext_slice, &rsa_keypair);
	let (account, increment) = utils::get_account_and_increment_from_plaintext(plaintext.clone());

    // read the counter state
	let mut state_vec: Vec<u8> = Vec::new();
	retval = utils::read_counterstate(&mut state_vec, COUNTERSTATE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

    let helper = DeSerializeHelper::<AllCounts>::new(state_vec);
    let mut counter = helper.decode().unwrap();

	// increment or create the counter and write state
	increment_or_insert_counter(&mut counter, &account, increment);
    retval = write_counter_state(counter);

	// get information for composing the extrinsic
	let nonce = U256::decode(&mut nonce_slice).unwrap();
	let _seed = _get_ecc_seed_file(&mut retval);
	let genesis_hash = utils::hash_from_slice(hash_slice);
	let call_hash = utils::blake2s(&plaintext);
	debug!("[Enclave]: Call hash {:?}", call_hash);

	let ex = compose_extrinsic(_seed, &call_hash, nonce, genesis_hash);

	let encoded = ex.encode();
	extrinsic_slize.clone_from_slice(&encoded);
    retval
}

#[no_mangle]
pub extern "C" fn get_counter(account: *const u8, account_size: u32, value: *mut u32) -> sgx_status_t {
	let mut state_vec: Vec<u8> = Vec::new();

	let account_slice = unsafe { slice::from_raw_parts(account, account_size as usize) };
	let acc_str = std::str::from_utf8(account_slice).unwrap();

	let retval = utils::read_counterstate(&mut state_vec, COUNTERSTATE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

	let helper = DeSerializeHelper::<AllCounts>::new(state_vec);
	let mut counter = helper.decode().unwrap();
	unsafe {
		let ref_mut = &mut *value;
		*ref_mut = *counter.entries.entry(acc_str.to_string()).or_insert(0);
	}
	retval
}

fn increment_or_insert_counter(counter: &mut AllCounts, name: &str, value: u32) {
	{
		let c = counter.entries.entry(name.to_string()).or_insert(0);
		*c += value;
	}
	if counter.entries.get(name).unwrap() == &value {
		info!("[Enclave] No counter found for '{}', adding new with initial value {}", name, value);
	} else {
		info!("[Enclave] Incremented counter for '{}'. New value: {:?}", name, counter.entries.get(name).unwrap());
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

    info!("[Enclave]: Restored sealed key pair with pubkey: {:?}", _pubkey.to_base58());

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
    entries: HashMap<String, u32>
}

// fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
//     unsafe {
//         sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
//     }
// }

fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
	unsafe {
		SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
	}
}


pub fn compose_extrinsic(seed: Vec<u8>, call_hash: &[u8], nonce: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let (_privkey, _pubkey) = keypair(&seed);

	let era = Era::immortal();
	let function = Call::SubstraTEEProxy(SubstraTEEProxyCall::confirm_call(call_hash.to_vec()));

    let index = Index::from(nonce.low_u64());
    let raw_payload = (Compact(index), function, era, genesis_hash);

    let sign = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		// should not be thrown as we calculate a 32 byte hash ourselves
        error!("unsupported payload size");
        signature(&[0u8; 64], &_privkey)
    } else {
        //println!("signing {}", HexDisplay::from(&payload));
        signature(payload, &_privkey)
    });

	let signerpub = ed25519::Public::from_raw(_pubkey);
	let signature =  ed25519::Signature::from_raw(sign);

	UncheckedExtrinsic::new_signed(
        index,
        raw_payload.1,
        signerpub.into(),
		signature.into(),
        era,
    )
}

