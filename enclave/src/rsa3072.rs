use std::sgxfs::SgxFile;
use std::vec::Vec;

use sgx_crypto_helper::rsa3072::{Rsa3072KeyPair, Rsa3072PubKey};
use sgx_crypto_helper::RsaKeyPair;
use sgx_types::*;

use log::*;

use crate::utils::*;
use crate::constants::RSA3072_SEALED_KEY_FILE;

pub fn read_rsa_keypair() -> SgxResult<Rsa3072KeyPair> {
	let keyvec = read_file(RSA3072_SEALED_KEY_FILE)?;
	let key_json_str = std::str::from_utf8(&keyvec).unwrap();
	let pair: Rsa3072KeyPair = serde_json::from_str(&key_json_str).unwrap();
	Ok(pair)
}

pub fn read_rsa_pubkey() -> SgxResult<Rsa3072PubKey> {
	let pair = (read_rsa_keypair())?;
	let pubkey = pair.export_pubkey().unwrap();

	Ok(pubkey)
}

pub fn create_sealed_rsa3072_keypair_if_not_existent() -> SgxResult<sgx_status_t> {
	if SgxFile::open(RSA3072_SEALED_KEY_FILE).is_err() {
		info ! ("[Enclave] Keyfile not found, creating new! {}", RSA3072_SEALED_KEY_FILE);
		return create_sealed_rsa3072_keypair()
	}
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn create_sealed_rsa3072_keypair() -> Result<sgx_status_t, sgx_status_t> {
	let rsa_keypair = Rsa3072KeyPair::new().unwrap();
	let rsa_key_json = serde_json::to_string(&rsa_keypair).unwrap();
	// println!("[Enclave] generated RSA3072 key pair. Cleartext: {}", rsa_key_json);
	write_file(rsa_key_json.as_bytes(), RSA3072_SEALED_KEY_FILE)
}

pub fn store_rsa_key_pair(pair: &[u8]) -> SgxResult<sgx_status_t> {
	write_file(pair, RSA3072_SEALED_KEY_FILE)
}

pub fn decrypt_payload(ciphertext_slice: &[u8], rsa_pair: &Rsa3072KeyPair) -> Vec<u8> {
	let mut decrypted_buffer = Vec::new();
	rsa_pair.decrypt_buffer(ciphertext_slice, &mut decrypted_buffer).unwrap();
	decrypted_buffer
}
