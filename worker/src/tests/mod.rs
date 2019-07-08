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

use sgx_types::*;
use enclave_api::*;
use wasm::sgx_enclave_wasm_init;
use init_enclave::init_enclave;
use self::ecalls::*;
use self::integration_tests::*;
use clap::ArgMatches;

pub mod commons;
pub mod ecalls;
pub mod integration_tests;

pub fn run_enclave_tests(matches: &ArgMatches) {
	println!("*** Starting Test enclave");
	let enclave = init_enclave().unwrap();
	sgx_enclave_wasm_init(enclave.geteid()).unwrap();

	if matches.is_present("all") || matches.is_present("unit") {
		println!("Running unit Tests");
		run_enclave_unit_tests(enclave.geteid());
	}

	if matches.is_present("all") || matches.is_present("ecall") {
		println!("Running ecall Tests");
		run_ecalls(enclave.geteid());
	}

	if matches.is_present("all") || matches.is_present("integration") {
		println!("Running integration Tests");
		run_integration_tests(enclave.geteid());
	}
	println!("[+] All tests ended!");
}

fn run_enclave_unit_tests(eid: sgx_enclave_id_t) {

	let mut retval = 0usize;

	let result = unsafe {
		test_main_entrance(eid,
						   &mut retval)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			return;
		}
	}

	assert_eq!(retval, 0);
	println!("[+] unit_test ended!");
}



pub fn run_ecalls(eid: sgx_enclave_id_t) {
//	get_counter_works(eid);
//	perform_ra_works(eid);
	call_counter_wasm_works(eid);
	println!("[+] Ecall tests ended!");
}

pub fn run_integration_tests(eid: sgx_enclave_id_t) {
	//	perform_ra_works(eid);
	process_forwarded_payload_works(eid);
}
