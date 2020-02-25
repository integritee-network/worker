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

use clap::ArgMatches;

use crate::enclave::api::*;

use self::ecalls::*;
use self::integration_tests::*;

pub mod commons;
pub mod ecalls;
pub mod integration_tests;

pub fn run_enclave_tests(matches: &ArgMatches, port: &str) {
    println!("*** Starting Test enclave");
    let enclave = enclave_init().unwrap();
    let eid = enclave.geteid();

    if matches.is_present("all") || matches.is_present("unit") {
        println!("Running unit Tests");
        enclave_test(eid).unwrap();
        println!("[+] unit_test ended!");
    }

    if matches.is_present("all") || matches.is_present("ecall") {
        println!("Running ecall Tests");
        println!("  testing execute_stf()");
        execute_stf_works(eid);
        println!("  testing get_state()");
        get_state_works(eid);
        println!("[+] Ecall tests ended!");
    }

    if matches.is_present("all") || matches.is_present("integration") {
        // Fixme: It is not nice to need to forward the port. Better: setup a node running on some port before
        // running the tests.
        println!("Running integration Tests");
        println!("  testing perform_ra()");
        perform_ra_works(eid, port);
        println!("  testing process_forwarded_payload()");
        process_forwarded_payload_works(eid, port);
    }
    println!("[+] All tests ended!");
}
