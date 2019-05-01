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
use primitives::{ed25519};
//extern crate keyring;
extern crate node_runtime;
use node_runtime::{AccountId, UncheckedExtrinsic, CheckedExtrinsic, Call, BalancesCall, Hash, SubstraTEEProxyCall};
extern crate runtime_primitives;
use runtime_primitives::generic::Era;
extern crate parity_codec;
use parity_codec::{Encode, Compact};
extern crate primitive_types;
use primitive_types::U256;

use sgx_types::{sgx_status_t, sgx_sealed_data_t};
use sgx_types::marker::ContiguousMemory;
use sgx_tseal::{SgxSealedData};
use sgx_rand::{Rng, StdRng};
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


pub const RSA3072_SEALED_KEY_FILE: &'static str = "./bin/rsa3072_key_sealed.bin";
pub const COUNTERSTATE:            &'static str = "./bin/sealed_counter_state.bin";

/*
//FIXME: no_std broken here
/// Do a Blake2 256-bit hash and place result in `dest`.
pub fn blake2_256_into(data: &[u8], dest: &mut [u8; 32]) {
	dest.copy_from_slice(blake2_rfc::blake2b::blake2b(32, &[], data).as_bytes());
}

/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
	let mut r = [0; 32];
	blake2_256_into(data, &mut r);
	r
}
*/


// FIXME: [brenzi] why pass a filepath at all? I'd rather ise the hard-coded filename in relative path RSA3072_SEALED_KEY_FILE
// FIXME: no need to expose to app. check pre-existing file in here!
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

//FIXME: as above, don't pass filepath as an arg
// no need to expose to app
fn create_sealed_ed25519_keypair(filepath: *const u8, len: usize) -> sgx_status_t {
    let str_slice = unsafe { slice::from_raw_parts(filepath, len) };
    let mut filename = String::from("");
    for c in str_slice.iter() {
        filename.push(*c as char);
    }

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
    match SgxFile::create(&filename) {
        Ok(mut f) => match f.write_all(seed_json.as_bytes()) {
            Ok(()) => {
                println!("[Enclave +] Writing seed to '{}' successful", &filename);
                sgx_status_t::SGX_SUCCESS
            }
            Err(x) => {
                println!("[Enclave -] Writing seed to '{}' failed! {}", &filename, x);
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        },
        Err(x) => {
            println!("[Enclave !] Creating seed-file '{}' error! {}", &filename, x);
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
    //sgx_status_t::SGX_SUCCESS
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
    //FIXME: borrow checker trouble, -> should be fixed untested
	increment_or_insert_counter(&mut counter, v[0], number[0]);
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



fn to_sealed_log<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}




/*
trait Crypto {
	type Seed: AsRef<[u8]> + AsMut<[u8]> + Sized + Default;
	type Pair: Pair;
	fn pair_from_seed(seed: &Self::Seed) -> Self::Pair;
	fn pair_from_suri(phrase: &str, password: Option<&str>) -> Self::Pair {
		Self::pair_from_seed(&Self::seed_from_phrase(phrase, password))
	}
	fn ss58_from_pair(pair: &Self::Pair) -> String;
	fn public_from_pair(pair: &Self::Pair) -> Vec<u8>;
	fn seed_from_pair(_pair: &Self::Pair) -> Option<&Self::Seed> { None }
}


struct Ed25519;

impl Crypto for Ed25519 {
	type Seed = [u8; 32];
	type Pair = ed25519::Pair;
	fn pair_from_seed(seed: &Self::Seed) -> Self::Pair { ed25519::Pair::from_seed(seed.clone()) }
	fn pair_from_suri(suri: &str, password_override: Option<&str>) -> Self::Pair {
		ed25519::Pair::from_legacy_string(suri, password_override)
	}
	fn ss58_from_pair(pair: &Self::Pair) -> String { pair.public().to_ss58check() }
	fn public_from_pair(pair: &Self::Pair) -> Vec<u8> { (&pair.public().0[..]).to_owned() }
	fn seed_from_pair(pair: &Self::Pair) -> Option<&Self::Seed> { Some(pair.seed()) }
}

*/

pub fn compose_extrinsic(sender: &str, call_hash: Hash, index: U256, genesis_hash: Hash)  {
    //FIXME: don't generate new keypair, use the one supplied as argument

    let mut seed = [0u8; 32];
    let mut rand = StdRng::new().unwrap();
    rand.fill_bytes(&mut seed);
    // create ed25519 keypair
    let (_privkey, _pubkey) = keypair(&seed);
    
    let era = Era::immortal();
    
    //FIXME: use argument
    let call_hash_str = "0x01234".as_bytes().to_vec();
    let function = Call::SubstraTEEProxy(SubstraTEEProxyCall::confirm_call(call_hash_str));
    
    //let function = Call::Balances(BalancesCall::transfer(to.into(), amount));
    let raw_payload = (Compact(index), function, era, genesis_hash);
/*
    let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
        signature(&blake2_256(payload)[..], &_privkey);
    } else {
        //println!("signing {}", HexDisplay::from(&payload));
        signature(payload, &_privkey);
    });

    UncheckedExtrinsic::new_signed(
        index,
        raw_payload.1,
        _pubkey.into(),
        signature.into(),
        era,
    )
    */
}

//pub fn transfer(from: &str, to: &str, amount: U256, index: U256, genesis_hash: Hash) -> UncheckedExtrinsic {

  /*  
    let signer = Ed25519::pair_from_suri(from, Some(""));

    let to = ed25519::Public::from_string(to).ok().or_else(||
        ed25519::Pair::from_string(to, Some("")).ok().map(|p| p.public())
    ).expect("Invalid 'to' URI; expecting either a secret URI or a public URI.");
    let amount = Balance::from(amount.low_u128());
    let index = Index::from(index.low_u64());
    //let amount = str::parse::<Balance>("42")
    //	.expect("Invalid 'amount' parameter; expecting an integer.");
    //let index = str::parse::<Index>("0")
    //	.expect("Invalid 'index' parameter; expecting an integer.");

    let function = Call::Balances(BalancesCall::transfer(to.into(), amount));

    let era = Era::immortal();

    println!("using genesis hash: {:?}", genesis_hash);
/*		let mut gh: [u8; 32] = Default::default();
    gh.copy_from_slice(hex::decode(genesis_hash).unwrap().as_ref());
    let genesis_hash = Hash::from(gh);
    println!("using genesis hash to Hash: {:?}", gh);
*/
    //let genesis_hash: Hash = hex::decode(genesis_hash).unwrap();
    //let genesis_hash: Hash = hex!["61b81c075e1e54b17a2f2d685a3075d3e5f5c7934456dd95332e68dd751a4b40"].into();
//			let genesis_hash: Hash = hex!["58afaad82f5a80ecdc8e974f5d88c4298947260fb05e34f84a9eed18ec5a78f9"].into();
    let raw_payload = (Compact(index), function, era, genesis_hash);
    let signature = raw_payload.using_encoded(|payload| if payload.len() > 256 {
        signer.sign(&blake2_256(payload)[..])
    } else {
        println!("signing {}", HexDisplay::from(&payload));
        signer.sign(payload)
    });
    UncheckedExtrinsic::new_signed(
        index,
        raw_payload.1,
        signer.public().into(),
        signature.into(),
        era,
    )
    
}
*/

