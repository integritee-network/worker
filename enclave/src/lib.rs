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
extern crate schnorrkel;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
// use sgx_rand::{Rng, StdRng};
use sgx_serialize::{SerializeHelper, DeSerializeHelper};
#[macro_use]
extern crate sgx_serialize_derive;
// use sgx_serialize::*;

use std::io::{/*self, */Read, Write};
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
use schnorrkel::keys::MiniSecretKey;

pub const RSA3072_SEALED_KEY_FILE: &'static str = "./bin/rsa3072_key_sealed.bin";
pub const COUNTERSTATE:            &'static str = "./bin/sealed_counter_state.bin";

#[no_mangle]
pub extern "C" fn create_sealed_rsa3072_keypair(filepath: *const u8, len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(filepath, len) };
    let mut filename = String::from("");
    for c in str_slice.iter() {
        filename.push(*c as char);
    }

    // create a RSA keypair
    let rsa_keypair = Rsa3072KeyPair::new().unwrap();
    let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
    // println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);

    match SgxFile::create(&filename) {
        Ok(mut f) => match f.write_all(rsa_key_json.as_bytes()) {
            Ok(()) => {
                println!("[Enclave +] Writing keyfile '{}' successful", &filename);
                sgx_status_t::SGX_SUCCESS
            }
            Err(x) => {
                println!("[Enclave -] Writing keyfile '{}' failed! {}", &filename, x);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        },
        Err(x) => {
            println!("[Enclave !] Creating keyfile '{}' error! {}", &filename, x);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}

#[no_mangle]
pub extern "C" fn decrypt_and_process_payload(ciphertext: * mut u8, ciphertext_size: u32) -> sgx_status_t {

    let ciphertext_slice = unsafe { slice::from_raw_parts(ciphertext, ciphertext_size as usize) };

    //restore RSA key pair from file
    let mut keyvec: Vec<u8> = Vec::new();
    let key_json_str = match SgxFile::open(RSA3072_SEALED_KEY_FILE) {
        Ok(mut f) => match f.read_to_end(&mut keyvec) {
            Ok(len) => {
                println!("[Enclave] Read {} bytes from key file", len);
                std::str::from_utf8(&keyvec).unwrap()
            }
            Err(x) => {
                println!("[Enclave] Read key file failed {}", x);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        },
        Err(x) => {
            println!("[Enclave] get_sealed_pcl_key cannot open key file, please check if key is provisioned successfully! {}", x);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    //println!("[Enclave] key_json = {}", key_json_str);
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();

    let mut plaintext = Vec::new();
    rsa_keypair.decrypt_buffer(&ciphertext_slice, &mut plaintext).unwrap();

    let decrypted_string = String::from_utf8(plaintext).unwrap();
    println!("[Enclave] Decrypted data = {}", decrypted_string);

    let mut retval;
    let mut state_vec: Vec<u8> = Vec::new();

    match SgxFile::open(COUNTERSTATE) {
        Ok(mut f) => match f.read_to_end(&mut state_vec) {
            Ok(len) => {
                println!("[Enclave] Read {} bytes from storage file", len);
                retval = sgx_status_t::SGX_SUCCESS;
            }
            Err(x) => {
                println!("[Enclave] Read storage file failed {}", x);
                retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        },
        Err(x) => {
            println!("[Enclave] No storage file found. Error: {}", x);
            state_vec.push(0);
        }
    };

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
    // println!("counter = {:?}", counter);

    if let Some(x) = counter.entries.get_mut(v[0]) {
        *x += number[0];
        println!("[Enclave] Incremented counter for '{}'. New value: {:?}", v[0], counter.entries.get(v[0]).unwrap());
    } else {
        println!("[Enclave] No counter found for '{}', adding new with initial value {}", v[0], number[0]);
        counter.entries.insert(v[0].to_string(), number[0]);
    }

    retval = write_counter_state(counter);

    return retval;
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

fn from_sealed_log<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

#[no_mangle]
pub extern "C" fn get_rsa_encryption_pubkey(pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

    let pubkey_slice = unsafe { slice::from_raw_parts(pubkey, pubkey_size as usize) };

    //restore RSA key pair from file
    let mut keyvec: Vec<u8> = Vec::new();
    let key_json_str = match SgxFile::open(RSA3072_SEALED_KEY_FILE) {
        Ok(mut f) => match f.read_to_end(&mut keyvec) {
            Ok(len) => {
                println!("[Enclave] Read {} bytes from Key file", len);
                std::str::from_utf8(&keyvec).unwrap()
            }
            Err(x) => {
                println!("[Enclave] Read keyfile failed {}", x);
                return sgx_status_t::SGX_ERROR_UNEXPECTED;
            }
        },
        Err(x) => {
            println!("[Enclave] get_sealed_pcl_key cannot open keyfile, please check if key is provisioned successfully! {}", x);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };
    //println!("[Enclave] key_json = {}", key_json_str);
    let rsa_keypair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
 /*
 TODO: should only return pubkey, not keypair. But SgxRsaPubkey isnt serializable!

    let res = rsa_keypair.to_pubkey();
    let _pubkey = match res {
        Ok(x) => x,
        _ => {
            println!("[Enclave] couldn't create pubkey form rsa keypair");
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };

    let _pubkey_json = serde_json::to_string(&_pubkey).unwrap();
    println!("[Enclave] pubkey is: {}", _pubkey_json);
*/
    // now write pubkey back to caller
    let pubkey_slice = unsafe {
        slice::from_raw_parts_mut(pubkey, pubkey_size as usize)
    };

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

    //println!("[Enclave] enclave function success");
    sgx_status_t::SGX_SUCCESS
}

 #[derive(Serializable, DeSerializable, Debug)]
struct AllCounts {
    entries: HashMap<String, u8>
}

// fn create_counter_state() -> sgx_status_t {
//     let c_init = AllCounts{ entries: HashMap::<String, u8>::new() };

//     println!("[Enclave] Create empty storage file. Init new account map: {:?}", &c_init);
//     write_counter_state(c_init)
// }

fn write_counter_state(value: AllCounts) -> sgx_status_t {
    let helper = SerializeHelper::new();
    let c = helper.encode(value).unwrap();
    match SgxFile::create(COUNTERSTATE) {
        Ok(mut f) => match f.write_all(&c) {
            Ok(()) => {
                println!("[Enclave] SgxFile write storage file success!");
                sgx_status_t::SGX_SUCCESS
            }

            Err(x) => {
                println!("[Enclave] SgxFile write storage file failed! {}", x);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        },
        Err(x) => {
            println!("[Enclave] SgxFile create storage file {} error {}", COUNTERSTATE, x);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}


// -- the following code will be deleted in the future
/*
#[no_mangle]
pub extern "C" fn create_sealed_key(sealed_seed: * mut u8, sealed_seed_size: u32, pubkey: * mut u8, pubkey_size: u32) -> sgx_status_t {

    let mut seed = [0u8; 32];

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => { return sgx_status_t::SGX_ERROR_UNEXPECTED; },
    };
    rand.fill_bytes(&mut seed);

    let aad: [u8; 0] = [0_u8; 0];
    let result = SgxSealedData::<[u8; 32]>::seal_data(&aad, &seed);
    let sealed_data = match result {
        Ok(x) => x,
        Err(ret) => { return ret; },
    };

    let opt = to_sealed_log(&sealed_data, sealed_seed, sealed_seed_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // create ed25519 keypair
    let (_privkey, _pubkey) = keypair(&seed);

    println!("[Enclave] generated sealed keyair with pubkey: {:?}", _pubkey.to_base58());

    // now write pubkey back to caller
    let pubkey_slice = unsafe {
        slice::from_raw_parts_mut(pubkey, pubkey_size as usize)
    };
    pubkey_slice.clone_from_slice(&_pubkey);

    // also create a RSA keypair
    let rsa_keypair = Rsa3072KeyPair::new().unwrap();
    let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
    println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);

    match SgxFile::create(KEYFILE) {
        Ok(mut f) => match f.write_all(rsa_key_json.as_bytes()) {
            Ok(()) => {
                println!("[Enclave] SgxFile write key file success!");
                sgx_status_t::SGX_SUCCESS
            }
            Err(x) => {
                println!("[Enclave] SgxFile write key file failed! {}", x);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        },
        Err(x) => {
            println!("[Enclave] SgxFile create file {} error {}", KEYFILE, x);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }

    //sgx_status_t::SGX_SUCCESS
}


fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

*/