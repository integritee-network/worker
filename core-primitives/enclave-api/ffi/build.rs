/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use std::env;

fn main() {
	let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
	let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

	// NOTE: if the crate is a workspace member rustc-paths are relative from the root directory
	println!("cargo:rustc-link-search=native=./lib");
	println!("cargo:rustc-link-lib=static=Enclave_u");

	println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
	println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");
	match is_sim.as_ref() {
		"SW" => {
			println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
			println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
		},
		_ => {
			// HW by default
			println!("cargo:rustc-link-lib=dylib=sgx_urts");
			println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
		},
	}
}
