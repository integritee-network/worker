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

// substrate runtime flags
#![feature(structural_match)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![feature(rustc_attrs)]


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

extern crate primitives;
use primitives::{ed25519};

extern crate my_node_runtime;
use my_node_runtime::{UncheckedExtrinsic, Call, Hash, SubstraTEEProxyCall};
extern crate runtime_primitives;
use runtime_primitives::generic::Era;
use runtime_primitives::generic;
use runtime_primitives::traits::BlakeTwo256;

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

extern crate contract;
extern crate srml_support;

use std::sgxfs::SgxFile;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::collections::HashMap;
use std::string::ToString;

use crypto::ed25519::{keypair, signature};
use rust_base58::{ToBase58};
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair};

type Index = u64;

mod constants;
mod utils;
use constants::{RSA3072_SEALED_KEY_FILE, ED25519_SEALED_KEY_FILE, COUNTERSTATE};

#[no_mangle]
pub extern "C" fn get_rsa_encryption_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {

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
			println!("[Enclave] Keyfile not found, creating new! {}", x);
			retval = create_sealed_ed25519_seed();
		},
	}

	if retval != sgx_status_t::SGX_SUCCESS {
		// detailed error msgs are already printed in utils::write file
		return retval;
	}

	let _seed = _get_ecc_seed_file(&mut retval);
	let (_privkey, _pubkey) = keypair(&_seed);
	println!("[Enclave] restored ecc pubkey: {:?}", _pubkey.to_base58());

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

	let plaintext = utils::get_plaintext_from_encrypted_data(&ciphertext_slice, &rsa_keypair);
	let (account, increment) = utils::get_account_and_increment_from_plaintext(plaintext.clone());

    let mut state_vec: Vec<u8> = Vec::new();
	retval = utils::read_counterstate(&mut state_vec, COUNTERSTATE);

	if retval != sgx_status_t::SGX_SUCCESS {
		return retval;
	}

    let helper = DeSerializeHelper::<AllCounts>::new(state_vec);
    let mut counter = helper.decode().unwrap();

    //FIXME: borrow checker trouble, -> should be fixed, untested
	increment_or_insert_counter(&mut counter, &account, increment);
    retval = write_counter_state(counter);

	let nonce = U256::decode(&mut nonce_slice).unwrap();
	let _seed = _get_ecc_seed_file(&mut retval);

	let genesis_hash = utils::hash_from_slice(hash_slice);
	let call_hash = utils::blake2s(&plaintext);
//	println!("[Enclave]: Call hash {:?}", call_hash);

	let ex = compose_extrinsic(_seed, &call_hash, nonce, genesis_hash);

	let encoded = ex.encode();
	extrinsic_slize.clone_from_slice(&encoded);
    retval
}

#[no_mangle]
pub extern "C" fn get_counter(account: *const u8, account_size: u32, value: *mut u8) -> sgx_status_t {
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

fn increment_or_insert_counter(counter: &mut AllCounts, name: &str, value: u8) {
	{
		let c = counter.entries.entry(name.to_string()).or_insert(0);
		*c += value;
	}
	if counter.entries.get(name).unwrap() == &value {
		println!("[Enclave] No counter found for '{}', adding new with initial value {}", name, value);
	} else {
		println!("[Enclave] Incremented counter for '{}'. New value: {:?}", name, counter.entries.get(name).unwrap());
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

    println!("[Enclave]: restored sealed keyair with pubkey: {:?}", _pubkey.to_base58());

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


pub fn compose_extrinsic(seed: Vec<u8>, call_hash: &[u8], nonce: U256, genesis_hash: Hash) -> UncheckedExtrinsic {
	let (_privkey, _pubkey) = keypair(&seed);

	let era = Era::immortal();
	let function = Call::SubstraTEEProxy(SubstraTEEProxyCall::confirm_call(call_hash.to_vec()));

    let index = Index::from(nonce.low_u64());
    let raw_payload = (Compact(index), function, era, genesis_hash);

    let sign = raw_payload.using_encoded(|payload| if payload.len() > 256 {
		// should not be thrown as we calculate a 32 byte hash ourselves
        println!("unsupported payload size");
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
/////////////////////////////////////////////////////////////////////////////


use my_node_runtime::{AccountId, Indices, Nonce, opaque, Block, BlockNumber, AuthorityId, AuthoritySignature, Event};


#[structural_match]
#[rustc_copy_clone_marker]
pub struct Runtime;
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for Runtime {
    #[inline]
    fn clone(&self) -> Runtime { { *self } }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::marker::Copy for Runtime { }
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::PartialEq for Runtime {
    #[inline]
    fn eq(&self, other: &Runtime) -> bool {
        match *other { Runtime => match *self { Runtime => true, }, }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::Eq for Runtime {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () { { } }
}
impl ::srml_support::runtime_primitives::traits::GetNodeBlockType for Runtime
 {
    type
    NodeBlock
    =
    opaque::Block;
}
impl ::srml_support::runtime_primitives::traits::GetRuntimeBlockType for
 Runtime {
    type
    RuntimeBlock
    =
    Block;
}


#[allow(non_camel_case_types)]
#[structural_match]
pub enum Origin {
    system(system::Origin<Runtime>),

    #[allow(dead_code)]
    Void(::srml_support::Void),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Origin {
    #[inline]
    fn clone(&self) -> Origin {
        match (&*self,) {
            (&Origin::system(ref __self_0),) =>
            Origin::system(::core::clone::Clone::clone(&(*__self_0))),
            (&Origin::Void(ref __self_0),) =>
            Origin::Void(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Origin {
    #[inline]
    fn eq(&self, other: &Origin) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0),
                     &Origin::system(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    (&Origin::Void(ref __self_0),
                     &Origin::Void(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { false }
        }
    }
    #[inline]
    fn ne(&self, other: &Origin) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0),
                     &Origin::system(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    (&Origin::Void(ref __self_0),
                     &Origin::Void(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { true }
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Origin {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Origin<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<::srml_support::Void>;
        }
    }
}
#[allow(dead_code)]
impl Origin {
    pub const
    INHERENT:
    Self
    =
    Origin::system(system::RawOrigin::Inherent);
    pub const
    ROOT:
    Self
    =
    Origin::system(system::RawOrigin::Root);
    pub fn signed(by: <Runtime as system::Trait>::AccountId) -> Self {
        Origin::system(system::RawOrigin::Signed(by))
    }
}
impl From<system::Origin<Runtime>> for Origin {
    fn from(x: system::Origin<Runtime>) -> Self { Origin::system(x) }
}
impl Into<Option<system::Origin<Runtime>>> for Origin {
    fn into(self) -> Option<system::Origin<Runtime>> {
        if let Origin::system(l) = self { Some(l) } else { None }
    }
}
impl From<Option<<Runtime as system::Trait>::AccountId>> for Origin {
    fn from(x: Option<<Runtime as system::Trait>::AccountId>) -> Self {
        <system::Origin<Runtime>>::from(x).into()
    }
}

/// Wrapper for all possible log entries for the `$trait` runtime. Provides binary-compatible
/// `Encode`/`Decode` implementations with the corresponding `generic::DigestItem`.
#[allow(non_camel_case_types)]
#[structural_match]
pub struct Log(InternalLog);
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Log {
    #[inline]
    fn clone(&self) -> Log {
        match *self {
            Log(ref __self_0_0) =>
            Log(::core::clone::Clone::clone(&(*__self_0_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Log {
    #[inline]
    fn eq(&self, other: &Log) -> bool {
        match *other {
            Log(ref __self_1_0) =>
            match *self {
                Log(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
            },
        }
    }
    #[inline]
    fn ne(&self, other: &Log) -> bool {
        match *other {
            Log(ref __self_1_0) =>
            match *self {
                Log(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
            },
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Log {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        { let _: ::core::cmp::AssertParamIsEq<InternalLog>; }
    }
}
/// All possible log entries for the `$trait` runtime. `Encode`/`Decode` implementations
/// are auto-generated => it is not binary-compatible with `generic::DigestItem`.
#[allow(non_camel_case_types)]
#[structural_match]
pub enum InternalLog {
    system(system::Log<Runtime>),
    //consensus(consensus::Log<Runtime>),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for InternalLog {
    #[inline]
    fn clone(&self) -> InternalLog {
        match (&*self,) {
            (&InternalLog::system(ref __self_0),) =>
            InternalLog::system(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for InternalLog {
    #[inline]
    fn eq(&self, other: &InternalLog) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&InternalLog::system(ref __self_0),
                     &InternalLog::system(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { false }
        }
    }
    #[inline]
    fn ne(&self, other: &InternalLog) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&InternalLog::system(ref __self_0),
                     &InternalLog::system(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { true }
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for InternalLog {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Log<Runtime>>;
        }
    }
}
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_ENCODE_FOR_InternalLog: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate parity_codec as _parity_codec;
        impl _parity_codec::Encode for InternalLog {
            fn encode_to<EncOut: _parity_codec::Output>(&self,
                                                        dest: &mut EncOut) {
                match *self {
                    InternalLog::system(ref aa) => {
                        dest.push_byte(0usize as u8);
                        dest.push(aa);
                    }
                    _ => (),
                }
            }
        }
    };
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_DECODE_FOR_InternalLog: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate parity_codec as _parity_codec;
        impl _parity_codec::Decode for InternalLog {
            fn decode<DecIn: _parity_codec::Input>(input: &mut DecIn)
             -> Option<Self> {
                match input.read_byte()? {
                    x if x == 0usize as u8 => {
                        Some(InternalLog::system(_parity_codec::Decode::decode(input)?))
                    }
                    _ => None,
                }
            }
        }
    };
impl Log {
    /// Try to convert `$name` into `generic::DigestItemRef`. Returns Some when
    /// `self` is a 'system' log && it has been marked as 'system' in macro call.
    /// Otherwise, None is returned.
    #[allow(unreachable_patterns)]
    fn dref<'a>(&'a self)
     ->
         Option<::runtime_primitives::generic::DigestItemRef<'a, Hash, AuthorityId,
                                                        AuthoritySignature>> {
        match self.0 {
            InternalLog::system(system::RawLog::ChangesTrieRoot(ref v)) =>
            Some(::runtime_primitives::generic::DigestItemRef::ChangesTrieRoot(v)),
            _ => None,
        }
    }
}
impl ::runtime_primitives::traits::DigestItem for Log {
    type
    Hash
    =
    <::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                          AuthoritySignature> as
    ::runtime_primitives::traits::DigestItem>::Hash;
    type
    AuthorityId
    =
    <::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                          AuthoritySignature> as
    ::runtime_primitives::traits::DigestItem>::AuthorityId;
    fn as_authorities_change(&self) -> Option<&[Self::AuthorityId]> {
        self.dref().and_then(|dref| dref.as_authorities_change())
    }
    fn as_changes_trie_root(&self) -> Option<&Self::Hash> {
        self.dref().and_then(|dref| dref.as_changes_trie_root())
    }
}
impl From<::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                               AuthoritySignature>> for Log {
    /// Converts `generic::DigestItem` into `$name`. If `generic::DigestItem` represents
    /// a system item which is supported by the runtime, it is returned.
    /// Otherwise we expect a `Other` log item. Trying to convert from anything other
    /// will lead to panic in runtime, since the runtime does not supports this 'system'
    /// log item.
    #[allow(unreachable_patterns)]
    fn from(gen:
                ::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                                     AuthoritySignature>)
     -> Self {
        match gen {
            ::runtime_primitives::generic::DigestItem::ChangesTrieRoot(value) =>
            Log(InternalLog::system(system::RawLog::ChangesTrieRoot(value))),
            _ =>
            gen.as_other().and_then(|value|
                                        ::runtime_primitives::codec::Decode::decode(&mut &value[..])).map(Log).expect("not allowed to fail in runtime"),
        }
    }
}
impl ::runtime_primitives::codec::Decode for Log {
    /// `generic::DigestItem` binary compatible decode.
    fn decode<I: ::runtime_primitives::codec::Input>(input: &mut I)
     -> Option<Self> {
        let gen:
                ::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                                     AuthoritySignature> =
            ::runtime_primitives::codec::Decode::decode(input)?;
        Some(Log::from(gen))
    }
}
impl ::runtime_primitives::codec::Encode for Log {
    /// `generic::DigestItem` binary compatible encode.
    fn encode(&self) -> Vec<u8> {
        match self.dref() {
            Some(dref) => dref.encode(),
            None => {
                let gen:
                        ::runtime_primitives::generic::DigestItem<Hash,
                                                             AuthorityId,
                                                             AuthoritySignature> =
                    ::runtime_primitives::generic::DigestItem::Other(self.0.encode());
                gen.encode()
            }
        }
    }
}
impl From<system::Log<Runtime>> for Log {
    /// Converts single module log item into `$name`.
    fn from(x: system::Log<Runtime>) -> Self { Log(x.into()) }
}
impl From<system::Log<Runtime>> for InternalLog {
    /// Converts single module log item into `$internal`.
    fn from(x: system::Log<Runtime>) -> Self { InternalLog::system(x) }
}






impl system::Trait for Runtime {
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = Indices;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Nonce;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header digest type.
	type Digest = generic::Digest<Log>;
	/// The header type.
	type Header = generic::Header<BlockNumber, BlakeTwo256, Log>;
	/// The ubiquitous event type.
	type Event = Event;
	/// The ubiquitous log type.
	type Log = Log;
	/// The ubiquitous origin type.
	type Origin = Origin;
}

impl timestamp::Trait for Runtime {
	/// A timestamp: seconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = ();
}

impl contract::Trait for Runtime {

}
