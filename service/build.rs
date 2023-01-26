// Copyright (C) 2017-2018 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::env;

fn main() {
	let sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
	let is_sim = env::var("SGX_MODE").unwrap_or_else(|_| "HW".to_string());

	// NOTE: if the crate is a workspace member rustc-paths are relative from the root directory
	println!("cargo:rustc-link-search=native=./lib");
	println!("cargo:rustc-link-lib=static=Enclave_u");

	println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
	println!("cargo:rustc-link-lib=static=sgx_uprotected_fs");
	// if the linker failed to find libsgx_dcap_ql.so, please make sure that
	// (1) libsgx-dcap-ql is installed
	// (2) libsgx_dcap_ql.so exists. typicall at /usr/lib/x86_64-linux-gnu
	// if libsgx_dcap_ql.so.1 is there, but no libsgx-dcap_ql,
	// just create a symlink by
	// ln -s libsgx_dcap_ql.so.1 libsgx_dcap_ql.so
	println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");
	println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
	println!("cargo:rustc-link-lib=dylib=dcap_quoteprov");
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
