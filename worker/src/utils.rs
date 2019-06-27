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

use log::*;
use std::slice;
use std::path::Path;
use std::fs;
use std::io::prelude::*;
use std::fs::File;
use constants::*;
use sgx_types::{sgx_status_t};

pub fn check_files() -> u8 {
	debug!("*** Check files");

	let mut missing_files = 0;
	missing_files += file_missing(ENCLAVE_FILE);
	missing_files += file_missing(RSA_PUB_KEY);
	missing_files += file_missing(ECC_PUB_KEY);

	// remote attestation files
	missing_files += file_missing(RA_SPID);
	missing_files += file_missing(RA_CERT);
	missing_files += file_missing(RA_KEY);

	missing_files
}

fn file_missing(path: &str) -> u8 {
	if Path::new(path).exists() {
		debug!("File '{}' found", path);
		0
	} else {
		error!("File '{}' not found", path);
		1
	}
}

#[no_mangle]
pub unsafe extern "C" fn ocall_read_file (
					p_filename      : *const u8,
					filename_len    : u32,
					p_content       : *mut u8,
					content_len     : u32,
					p_return_len    : *mut u32) -> sgx_status_t {

	let mut rt : sgx_status_t = sgx_status_t::SGX_SUCCESS;

	let content_slice  = slice::from_raw_parts_mut(p_content, content_len as usize);
	let filename_slice = slice::from_raw_parts(p_filename, filename_len as usize);
	let filename = String::from_utf8(filename_slice.to_vec()).unwrap();

	let mut buffer = Vec::new();
	match File::open(&filename) {
		Ok(mut f) => match f.read_to_end(&mut buffer) {
			Ok(len) => {
				info!("[Enclave] Read {} bytes from counter state '{}'", len, filename);
				debug!("          data read: {:?}", buffer);
				*p_return_len = len as u32;
			}
			Err(x) => {
				error!("[Enclave] Read counter state '{}' failed. {}", filename, x);
				rt = sgx_status_t::SGX_ERROR_UNEXPECTED;
			}
		},
		Err(x) => {
			error!("[Enclave] Can't get counter state '{}'! {}", filename, x);
			*p_return_len = 1;
			buffer.push(0);
		}
	}

	// split the content_slice at the length of read data
	let (left, right) = content_slice.split_at_mut(*p_return_len as usize);
	left.clone_from_slice(&buffer);
	right.iter_mut().for_each(|x| *x = 0x20);

	rt
}

#[no_mangle]
pub unsafe extern "C" fn ocall_write_file (
					p_content          : *const u8,
					content_length     : u32,
					p_filename         : *const u8,
					filename_length    : u32) -> sgx_status_t {

	let content_slice  = slice::from_raw_parts(p_content, content_length as usize);
	let filename_slice = slice::from_raw_parts(p_filename, filename_length as usize);
	let filename = String::from_utf8(filename_slice.to_vec()).unwrap();

	match fs::write(&filename, content_slice) {
		Err(x) => {
			error!("[-] Failed to write '{}'. {}", &filename, x);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		_ => {
			info!("[+] File '{}' written successfully", &filename);
			sgx_status_t::SGX_SUCCESS
		}
	}
}
