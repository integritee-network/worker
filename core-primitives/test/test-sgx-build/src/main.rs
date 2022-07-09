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

#![feature(start, libc, lang_items)]
#![feature(alloc_error_handler)]
#![no_std]
#![no_main]

extern crate sgx_tstd as std;

// DUT
extern crate ita_exchange_oracle;

// The libc crate allows importing functions from C.
extern crate libc;

// A list of C functions that are being imported
extern "C" {
	pub fn printf(format: *const u8, ...) -> i32;
}

#[no_mangle]
// The main function, with its input arguments ignored, and an exit status is returned
pub extern "C" fn main(_nargs: i32, _args: *const *const u8) -> i32 {
	// Print "Hello, World" to stdout using printf
	unsafe {
		printf(b"Hello, World!\n" as *const u8);
	}

	// Exit with a return status of 0.
	0
}