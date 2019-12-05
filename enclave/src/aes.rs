use std::vec::Vec;

use sgx_rand::{Rng, StdRng};
use sgx_types::*;

use aes::Aes128;
use ofb::Ofb;
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};

use crate::constants::AES_KEY_FILE_AND_INIT_V;
use crate::utils::*;

type AesOfb = Ofb<Aes128>;

pub fn read_or_create_aes_key_iv() -> SgxResult<(Vec<u8>, Vec<u8>)> {
	match read_aes_key_and_iv() {
		Ok((k,i)) => Ok((k, i)),
		Err(_) => {
			create_sealed_aes_key_and_iv()?;
			read_aes_key_and_iv()
		},
	}
}

pub fn read_aes_key_and_iv() -> SgxResult<(Vec<u8>, Vec<u8>)> {
	let key_iv = read_file(AES_KEY_FILE_AND_INIT_V)?;
	Ok((key_iv[..16].to_vec(), key_iv[16..].to_vec()))
}

pub fn store_aes_key_and_iv(key: [u8; 16], iv: [u8; 16]) -> SgxResult<sgx_status_t>{
	let mut key_iv = key.to_vec();
	key_iv.extend_from_slice(&iv);
	write_file(&key_iv, AES_KEY_FILE_AND_INIT_V)
}

pub fn create_sealed_aes_key_and_iv() -> SgxResult<sgx_status_t> {
	let mut key_iv = [0u8; 32];

	let mut rand = match StdRng::new() {
		Ok(rng) => rng,
		Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};

	rand.fill_bytes(&mut key_iv);
	write_file(&key_iv, AES_KEY_FILE_AND_INIT_V)
}

/// If AES acts on the encrypted data it decrypts and vice versa
pub fn aes_de_or_encrypt(bytes: &mut Vec<u8>) -> SgxResult<sgx_status_t> {
	let (key, iv) = read_or_create_aes_key_iv()?;
	AesOfb::new_var(&key, &iv).unwrap().apply_keystream(bytes);
	Ok(sgx_status_t::SGX_SUCCESS)
}
