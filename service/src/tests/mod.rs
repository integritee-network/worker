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

pub mod commons;
pub mod mock;

#[cfg(test)]
pub mod mocks;

// Todo: Revive when #1451 is resolved
// #[cfg(test)]
// pub mod parentchain_handler_test;

#[cfg(feature = "link-binary")]
use clap::ArgMatches;

#[cfg(feature = "link-binary")]
pub fn run_enclave_tests(matches: &ArgMatches) {
	use crate::{config::Config, enclave::api::*, setup};
	use itp_enclave_api::enclave_test::EnclaveTest;

	println!("*** Starting Test enclave");
	let mut config = Config::from(matches).with_test_data_dir();
	println!("   creating temporary working dir for tests: {:?}", config.data_dir());
	std::fs::create_dir_all(config.data_dir()).unwrap();
	setup::purge_shards_unless_protected(config.data_dir()).unwrap();
	setup::purge_integritee_lcdb_unless_protected(config.data_dir()).unwrap();
	setup::purge_target_a_lcdb_unless_protected(config.data_dir()).unwrap();
	setup::purge_target_b_lcdb_unless_protected(config.data_dir()).unwrap();

	let enclave = enclave_init(&config).unwrap();

	if matches.is_present("all") || matches.is_present("unit") {
		println!("Running unit Tests");
		enclave.test_main_entrance().unwrap();
		println!("[+] unit_test ended!");
	}
	// clean up test directory
	std::fs::remove_dir_all(config.data_dir()).unwrap();
	println!("[+] All tests ended!");
}
