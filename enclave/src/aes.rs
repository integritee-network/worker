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

use std::vec::Vec;

use sgx_rand::{Rng, StdRng};
use sgx_types::*;

use aes::Aes128;
use ofb::Ofb;
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};

use crate::constants::AES_KEY_FILE_AND_INIT_V;
use crate::io;

type AesOfb = Ofb<Aes128>;

pub fn read_or_create_sealed() -> SgxResult<(Vec<u8>, Vec<u8>)> {
	match read_sealed() {
		Ok((k,i)) => Ok((k, i)),
		Err(_) => {
			create_sealed()?;
			read_sealed()
		},
	}
}

pub fn read_sealed() -> SgxResult<(Vec<u8>, Vec<u8>)> {
	let key_iv = io::read_file(AES_KEY_FILE_AND_INIT_V)?;
	Ok((key_iv[..16].to_vec(), key_iv[16..].to_vec()))
}

pub fn seal(key: [u8; 16], iv: [u8; 16]) -> SgxResult<sgx_status_t>{
	let mut key_iv = key.to_vec();
	key_iv.extend_from_slice(&iv);
	io::write_file(&key_iv, AES_KEY_FILE_AND_INIT_V)
}

pub fn create_sealed() -> SgxResult<sgx_status_t> {
	let mut key_iv = [0u8; 32];

	let mut rand = match StdRng::new() {
		Ok(rng) => rng,
		Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};

	rand.fill_bytes(&mut key_iv);
	io::write_file(&key_iv, AES_KEY_FILE_AND_INIT_V)
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn de_or_encrypt(bytes: &mut Vec<u8>) -> SgxResult<sgx_status_t> {
	let (key, iv) = read_or_create_sealed()?;
	AesOfb::new_var(&key, &iv).unwrap().apply_keystream(bytes);
	Ok(sgx_status_t::SGX_SUCCESS)
}
