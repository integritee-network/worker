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
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;

use crypto::blake2s::Blake2s;
use log::*;
use my_node_runtime::Hash;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use sgx_crypto_helper::RsaKeyPair;
use sgx_rand::{Rng, StdRng};
use sgx_types::*;

use constants::{ED25519_SEALED_KEY_FILE, RSA3072_SEALED_KEY_FILE};
use std::io::{Read, Write};
use std::sgxfs::SgxFile;
use std::vec::Vec;
use std::slice;
use sgx_crypto_helper::RsaKeyPair;
use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair};

use sgx_types::{sgx_status_t};
use my_node_runtime::Hash;
use crypto::blake2s::Blake2s;

use blake2_no_std::blake2b::blake2b;

use constants::{RSA3072_SEALED_KEY_FILE, COUNTERSTATE};

use aes::Aes128;
use ofb::Ofb;
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};

extern "C" {
	pub fn ocall_write_file(
		ret_val            : *mut sgx_status_t,
		p_content          : *const u8,
		content_length     : u32,
		p_filename         : *const u8,
		filename_length    : u32) -> sgx_status_t;

	pub fn ocall_read_file(
		ret_val         : *mut sgx_status_t,
		p_filename      : *const u8,
		filename_len    : u32,
		p_content       : *mut u8,
		content_len     : u32,
		return_len      : *mut u32) -> sgx_status_t;
}

pub fn read_rsa_keypair(status: &mut sgx_status_t) -> Rsa3072KeyPair {
	let keyvec = read_file(RSA3072_SEALED_KEY_FILE)?;
	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
	let pair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
	Ok(pair)
}

pub fn read_rsa_pubkey() -> SgxResult<Rsa3072PubKey> {
	let pair = r#try!(read_rsa_keypair());
	let pubkey = pair.export_pubkey().unwrap();

	Ok(pubkey)
}

pub fn get_ecc_seed() -> SgxResult<Vec<u8>> {
	read_file(ED25519_SEALED_KEY_FILE)
}

pub fn create_sealed_ed25519_seed() -> SgxResult<sgx_status_t> {
	let mut seed = [0u8; 32];
	let mut rand = match StdRng::new() {
		Ok(rng) => rng,
		Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};
	rand.fill_bytes(&mut seed);

	write_file(&seed, ED25519_SEALED_KEY_FILE)
}

pub fn write_file(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
	match SgxFile::create(filepath) {
		Ok(mut f) => match f.write_all(bytes) {
			Ok(()) => {
				info!("[Enclave] Writing keyfile '{}' successful", filepath);
				Ok(sgx_status_t::SGX_SUCCESS)
			}
			Err(x) => {
				error!("[Enclave -] Writing keyfile '{}' failed! {}", filepath, x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			error!("[Enclave !] Creating keyfile '{}' error! {}", filepath, x);
			Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}
	}
}

pub fn read_file(filepath: &str) -> SgxResult<Vec<u8>> {
	let mut keyvec: Vec<u8> = Vec::new();
	match SgxFile::open(filepath) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(len) => {
				info!("[Enclave] Read {} bytes from key file", len);
				Ok(keyvec)
			}
			Err(x) => {
				error!("[Enclave] Read key file failed {}", x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			error!("[Enclave] get_sealed_pcl_key cannot open key file, please check if key is provisioned successfully! {}", x);
			Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}
	}
}

// FIXME: think about how statevec should be handled in case no counter exist such that we
// only need one read function. Maybe search and init COUNTERSTATE file upon enclave init?
pub fn read_counterstate(filepath: &str) -> SgxResult<Vec<u8>> {
	let mut state_vec: Vec<u8> = Vec::new();
	match SgxFile::open(filepath) {
		Ok(mut f) => match f.read_to_end(&mut state_vec) {
			Ok(len) => {
				info!("[Enclave] Read {} bytes from counter file", len);
				Ok(state_vec)
			}
			Err(x) => {
				error!("[Enclave] Read counter file failed {}", x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			error!("[Enclave] Can't get counter state '{}'! {}", COUNTERSTATE, x);
			state_vec.push(0);
			Ok(state_vec)
		}
	}
}

	// OFB mode implementation is generic over block ciphers
	// we will create a type alias for convenience
	type AesOfb = Ofb<Aes128>;

	let key = b"very secret key.";	// 16 bytes
	let iv  = b"unique init vect";	// 16 bytes
	let plaintext = b"The quick brown fox jumps over the lazy dog.";

	let mut buffer = plaintext.to_vec();

	// apply keystream (encrypt)
	AesOfb::new_var(key, iv).unwrap().apply_keystream(&mut buffer);
	println!("buffer encrypted = {:?}", buffer);

	// and decrypt it back
	AesOfb::new_var(key, iv).unwrap().apply_keystream(&mut buffer);
	println!("buffer decrypted = {:?}", buffer);

	println!("ending encryption");
	println!("--------------------------------------------------------------------");
*/

	let v = unsafe { slice::from_raw_parts(content_buf.as_ptr(), return_len as usize) };
	*state_vec = v.to_vec();

	result
}

// write the encrypted counter state
pub fn write_counterstate(bytes: &[u8]) -> sgx_status_t {
	println!("data to be written: {:?}", bytes);

	match sgxfs::write("./bin/sealed_counter_state2.bin", bytes) {
		Err(x) => { error!("Failed to write sealed counter state 2"); },
		_      => { println!("Sealed counter state 2 written"); }
	}

	match SgxFile::create(COUNTERSTATE) {
		Ok(mut f) => match f.write_all(bytes) {
			Ok(()) => {
				info!("[Enclave] Writing counter state '{}' successful", COUNTERSTATE);
				sgx_status_t::SGX_SUCCESS
			}
			Err(x) => {
				error!("[Enclave] Writing counter state '{}' failed! {}", COUNTERSTATE, x);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			}
		},
		Err(x) => {
			error!("[Enclave] Creating counter state '{}' error! {}", COUNTERSTATE, x);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		}
	}
}

pub fn decode_payload(ciphertext_slice: &[u8], rsa_pair: &Rsa3072KeyPair) -> Vec<u8> {
	let mut decrypted_buffer = Vec::new();
	rsa_pair.decrypt_buffer(ciphertext_slice, &mut decrypted_buffer).unwrap();
	decrypted_buffer
}

pub fn hash_from_slice(hash_slize: &[u8]) -> Hash {
	let mut g = [0; 32];
	g.copy_from_slice(&hash_slize[..]);
	Hash::from(&mut g)
}

pub fn blake2s(plaintext: &[u8]) -> [u8; 32] {
	let mut call_hash: [u8; 32] = Default::default();
	Blake2s::blake2s(&mut call_hash, &plaintext[..], &[0; 32]);
	call_hash
}

// Same functions as in substrate/core/primitives, but using the no_std blake2_rfc
/// Do a Blake2 256-bit hash and place result in `dest`.
fn blake2_256_into(data: &[u8], dest: &mut [u8; 32]) {
	dest.copy_from_slice(blake2b(32, &[], data).as_bytes());
}

/// Do a Blake2 256-bit hash and return result.
pub fn blake2_256(data: &[u8]) -> [u8; 32] {
	let mut r = [0; 32];
	blake2_256_into(data, &mut r);
	r
}
