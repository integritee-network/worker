use std::vec::Vec;

use sgx_types::*;

use log::*;

use crate::aes::*;
use crate::utils::*;

pub fn read_state_from_file(path: &str) -> SgxResult<Vec<u8>> {
	let mut bytes = match read_plaintext(path) {
		Ok(vec) => match vec.len() {
			0 => return Ok(vec),
			_ => vec,
		},
		Err(e) => return Err(e),
	};

	aes_de_or_encrypt(&mut bytes)?;
	debug!("buffer decrypted = {:?}", bytes);

	Ok(bytes)
}

pub fn write_state_to_file(bytes: &mut Vec<u8>, path: &str) -> SgxResult<sgx_status_t> {
	debug!("plaintext data to be written: {:?}", bytes);

	aes_de_or_encrypt(bytes)?;

	write_plaintext(&bytes, path)?;
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn test_encrypted_state_io_works() {
	let path = "test_state_file.bin";
	let plaintext = b"The quick brown fox jumps over the lazy dog.";
	create_sealed_aes_key_and_iv().unwrap();

	aes_de_or_encrypt(&mut plaintext.to_vec()).unwrap();
	write_state_to_file(&mut plaintext.to_vec(), path).unwrap();
	let state: Vec<u8> = read_state_from_file(path).unwrap();

	assert_eq!(state, plaintext.to_vec());
	std::fs::remove_file(path).unwrap();
}
