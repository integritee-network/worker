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

use crate::{config::Config, enclave::api::*, setup};
use clap::ArgMatches;
use itp_enclave_api::enclave_test::EnclaveTest;

pub mod commons;
pub mod mock;

#[cfg(test)]
pub mod mocks;

#[cfg(test)]
pub mod parentchain_handler_test;

pub fn run_enclave_tests(matches: &ArgMatches) {
	println!("*** Starting Test enclave");
	let config = Config::from(matches);
	setup::purge_files_from_dir(config.data_dir()).unwrap();
	let enclave = enclave_init(&config).unwrap();

	if matches.is_present("all") || matches.is_present("unit") {
		println!("Running unit Tests");
		enclave.test_main_entrance().unwrap();
		println!("[+] unit_test ended!");
	}

	println!("[+] All tests ended!");
}
