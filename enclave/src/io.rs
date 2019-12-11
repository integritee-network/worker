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
use std::fs::File;
use std::io::{Read, Write};
use std::sgxfs::SgxFile;
use std::string::String;
use std::vec::Vec;

use sgx_types::*;

use log::*;

pub fn write_file(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
	match SgxFile::create(filepath) {
		Ok(mut f) => match f.write_all(bytes) {
			Ok(()) => {
				info!("[Enclave] Writing keyfile '{}' successful", filepath);
				Ok(sgx_status_t::SGX_SUCCESS)
			}
			Err(x) => {
				error!("[Enclave -] Writing keyfile '{}' failed! Err: {}", filepath, x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			error!("[Enclave !] Creating keyfile '{}' Err: {}", filepath, x);
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
				error!("[Enclave] Read sealed file failed {}: Err {}", filepath, x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			info!("[Enclave] Can't find sealed file {} Err: {}" , filepath, x);
			Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}
	}
}

pub fn read_plaintext(filepath: &str) -> SgxResult<Vec<u8>> {
	let mut state_vec: Vec<u8> = Vec::new();
	match File::open(filepath) {
		Ok(mut f) => match f.read_to_end(&mut state_vec) {
			Ok(len) => {
				info!("[Enclave] Read {} bytes from file", len);
				Ok(state_vec)
			}
			Err(x) => {
				error!("[Enclave] Reading '{}' failed", x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			info!("[Enclave] File '{}' not found! Err: {}", filepath, x);
			Ok(state_vec)
		}
	}
}

pub fn read_to_string(filepath: &str) -> SgxResult<String> {
	let mut f = match File::open(filepath) {
		Ok(f) => f,
		Err(_) => {
			error!("cannot open the '{}'", filepath);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
		},
	};
	let mut contents = String::new();
	if f.read_to_string(&mut contents).is_err() {
		error!("cannot read the '{}'", filepath);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
	}
	Ok(contents)
}

pub fn write_plaintext(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
	match File::create(filepath) {
		Ok(mut f) => match f.write_all(bytes) {
			Ok(()) => {
				info!("[Enclave] Writing to file '{}' successful", filepath);
				Ok(sgx_status_t::SGX_SUCCESS)
			}
			Err(x) => {
				error!("[Enclave] Writing to '{}' failed! {}", filepath, x);
				Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
			}
		},
		Err(x) => {
			error!("[Enclave] Creating file '{}' error! {}", filepath, x);
			Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}
	}
}
