use sgx_types::*;
use enclave_api::*;
use wasm::sgx_enclave_wasm_init;
use init_enclave::init_enclave;
use self::ecalls::*;
use self::integration_tests::*;
use self::commons::*;

pub mod commons;
pub mod ecalls;
pub mod integration_tests;

pub fn run_enclave_tests() {
	println!("*** Starting enclave");
	let enclave = init_enclave().unwrap();
	sgx_enclave_wasm_init(enclave.geteid()).unwrap();

//	run_enclave_unit_tests(enclave.geteid());
	run_ecalls(enclave.geteid());

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
}
