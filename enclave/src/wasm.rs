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

#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use std::sync::SgxMutex;
use sgxwasm::SpecDriver;
use sgx_types::*;

// lazy_static!{
	// static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
// }

#[no_mangle]
pub extern "C" fn sgxwasm_init() -> sgx_status_t {
	let mut sd = SPECDRIVER.lock().unwrap();
	*sd = SpecDriver::new();
	sgx_status_t::SGX_SUCCESS
}
