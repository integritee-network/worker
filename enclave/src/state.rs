use std::vec::Vec;

use sgx_serialize::SerializeHelper;
use sgx_types::*;

use log::*;

use substratee_stf::State;

use crate::aes;
use crate::utils::*;

pub fn read(path: &str) -> SgxResult<Vec<u8>> {
	let mut bytes = match read_plaintext(path) {
		Ok(vec) => match vec.len() {
			0 => return Ok(vec),
			_ => vec,
		},
		Err(e) => return Err(e),
	};

	aes::de_or_encrypt(&mut bytes)?;
	debug!("buffer decrypted = {:?}", bytes);

	Ok(bytes)
}

pub fn write_encrypted(bytes: &mut Vec<u8>, path: &str) -> SgxResult<sgx_status_t> {
	debug!("plaintext data to be written: {:?}", bytes);

	aes::de_or_encrypt(bytes)?;

	write_plaintext(&bytes, path)?;
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn encrypt(value: State) -> Result<Vec<u8>, sgx_status_t> {
	let helper = SerializeHelper::new();
	let mut c = helper.encode(value).unwrap();
	aes::de_or_encrypt(&mut c)?;
	Ok(c)
}

pub fn test_encrypted_state_io_works() {
	let path = "test_state_file.bin";
	let plaintext = b"The quick brown fox jumps over the lazy dog.";
	aes::create_sealed().unwrap();

	aes::de_or_encrypt(&mut plaintext.to_vec()).unwrap();
	write_encrypted(&mut plaintext.to_vec(), path).unwrap();
	let state: Vec<u8> = read(path).unwrap();

	assert_eq!(state, plaintext.to_vec());
	std::fs::remove_file(path).unwrap();
}
