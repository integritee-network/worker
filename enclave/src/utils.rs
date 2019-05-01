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
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;

use std::sgxfs::SgxFile;
use std::io::{Read, Write};
use std::vec::Vec;

use sgx_types::sgx_status_t;


pub fn write_file(bytes: &[u8] ,filepath: &str) -> sgx_status_t {
	match SgxFile::create(filepath) {
		Ok(mut f) => match f.write_all(bytes) {
			Ok(()) => {
				println!("[Enclave +] Writing keyfile '{}' successful", filepath);
				sgx_status_t::SGX_SUCCESS
			}
			Err(x) => {
				println!("[Enclave -] Writing keyfile '{}' failed! {}", filepath, x);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			}
		},
		Err(x) => {
			println!("[Enclave !] Creating keyfile '{}' error! {}", filepath, x);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		}
	}
}

pub fn read_file(mut keyvec: &mut Vec<u8>, filepath: &str) -> sgx_status_t {
	match SgxFile::open(filepath) {
		Ok(mut f) => match f.read_to_end(&mut keyvec) {
			Ok(len) => {
				println!("[Enclave] Read {} bytes from key file", len);
				return sgx_status_t::SGX_SUCCESS;
			}
			Err(x) => {
				println!("[Enclave] Read key file failed {}", x);
				return sgx_status_t::SGX_ERROR_UNEXPECTED;
			}
		},
		Err(x) => {
			println!("[Enclave] get_sealed_pcl_key cannot open key file, please check if key is provisioned successfully! {}", x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED;
		}
	};
}

