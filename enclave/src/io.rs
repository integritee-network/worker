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

use crate::utils::UnwrapOrSgxErrorUnexpected;

pub fn read_file(filepath: &str) -> SgxResult<Vec<u8>> {
	SgxFile::open(filepath)
		.map(|f| read(f))
		.sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?
}

pub fn read_plaintext(filepath: &str) -> SgxResult<Vec<u8>> {
	File::open(filepath)
		.map(|f| read(f))
		.sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?
}

pub fn read<F: Read>(mut file: F) -> SgxResult<Vec<u8>> {
	let mut read_data: Vec<u8> = Vec::new();
	file.read_to_end(&mut read_data)
		.sgx_error_with_log(&format!("[Enclave] Reading File failed!"))?;

	Ok(read_data)
}

pub fn read_to_string(filepath: &str) -> SgxResult<String> {
	let mut contents = String::new();
	File::open(filepath)
		.map(|mut f| f.read_to_string(&mut contents))
		.sgx_error_with_log(&format!("[Enclave] Could not read '{}'", filepath))?
		.sgx_error_with_log(&format!("[Enclave] File '{}' not found!", filepath))?;

	Ok(contents)
}

pub fn write_file(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
	SgxFile::create(filepath)
		.map(|f| write(bytes, f))
		.sgx_error_with_log(&format!("[Enclave] Creating '{}' failed", filepath))?
}

pub fn write_plaintext(bytes: &[u8], filepath: &str) -> SgxResult<sgx_status_t> {
	File::create(filepath)
		.map(|f| write(bytes, f))
		.sgx_error_with_log(&format!("[Enclave] Creating '{}' failed", filepath))?
}

pub fn write<F: Write>(bytes: &[u8], mut file: F) -> SgxResult<sgx_status_t> {
	file.write_all(bytes)
		.sgx_error_with_log(&format!("[Enclave] Writing File failed!"))?;

	Ok(sgx_status_t::SGX_SUCCESS)
}
