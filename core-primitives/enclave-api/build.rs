/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
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

fn main() {
	// If the linker failed to find libsgx_dcap_ql.so, please make sure that
	// (1) libsgx-dcap-ql is installed
	// (2) libsgx_dcap_ql.so exists. typicall at /usr/lib/x86_64-linux-gnu
	// if libsgx_dcap_ql.so.1 is there, but no libsgx-dcap_ql,
	// just create a symlink by
	// ln -s libsgx_dcap_ql.so.1 libsgx_dcap_ql.so
	println!("cargo:rustc-link-lib=dylib=sgx_dcap_ql");
	println!("cargo:rustc-link-lib=dylib=sgx_dcap_quoteverify");
}
