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

use sgx_types::*;

use log::*;

use crate::aes;
use crate::io;

pub fn read(path: &str) -> SgxResult<Vec<u8>> {
	let mut bytes = match io::read(path) {
		Ok(vec) => match vec.len() {
			0 => return Ok(vec),
			_ => vec,
		},
		Err(e) => return Err(e),
	};

	aes::de_or_encrypt(&mut bytes)?;
	debug!("    [Enclave] buffer decrypted = {:?}", bytes);

	Ok(bytes)
}

pub fn write_encrypted(bytes: &mut Vec<u8>, path: &str) -> SgxResult<sgx_status_t> {
	debug!("    [Enclave] Plaintext data to be written: {:?}", bytes);

	aes::de_or_encrypt(bytes)?;

	io::write(&bytes, path)?;
	Ok(sgx_status_t::SGX_SUCCESS)
}

pub fn encrypt(mut state: Vec<u8>) -> Result<Vec<u8>, sgx_status_t> {
	aes::de_or_encrypt(&mut state)?;
	Ok(state)
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
