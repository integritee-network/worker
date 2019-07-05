use sgx_types::*;
use enclave_api::*;
use utils;
use wasm::sgx_enclave_wasm_init;
use init_enclave::init_enclave;
use log::*;
use constants::*;
use substrate_api_client::Api;
use std::fs;
use primitive_types::U256;
use enclave_wrappers::get_account_nonce;
use parity_codec::Encode;

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
	perform_ra_works(eid);
	println!("[+] Ecall tests ended!");
}

fn get_counter_works(eid: sgx_enclave_id_t) {
	let hash: Vec<String> = utils::get_wasm_hash();
	println!("Wasm Hash: {:?}", hash[0]);
	println!("Wasm Binary : {:?}", hash[1]);

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let account ="Alice";
	let mut value = 0u32;

	let result = unsafe {
		get_counter(eid,
					&mut retval,
					account.as_ptr(),
					account.len() as u32,
					&mut value)
	};

	println!("{} value: {}", account, value);
}

fn perform_ra_works(eid: sgx_enclave_id_t) {
//	let hash: Vec<String> = utils::get_wasm_hash();
//	println!("Wasm Hash: {:?}", hash[0]);
//	println!("Wasm Binary : {:?}", hash[1]);

	// start the substrate-api-client to communicate with the node
	let mut api = Api::new(format!("ws://127.0.0.1:9991"));
	api.init();

	let w_url = "ws://127.0.0.1:2001";
	let genesis_hash = api.genesis_hash.unwrap().as_bytes().to_vec();

	// get the public signing key of the TEE
	let mut key = [0; 32];
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ECC public key file");
	key.copy_from_slice(&ecc_key[..]);
	debug!("[+] Got ECC public key of TEE = {:?}", key);

	// get enclaves's account nonce
	let nonce = get_account_nonce(&api, key);
	let nonce_bytes = U256::encode(&nonce);
	debug!("Enclave nonce = {:?}", nonce);

	// prepare the unchecked extrinsic
	// the size is determined in the enclave
	let unchecked_extrinsic_size = 5000;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
	let mut status = sgx_status_t::SGX_ERROR_UNEXPECTED;
	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back
	println!("*** Perform a remote attestation of the enclave");
	let result = unsafe {
		perform_ra(
			eid,
			&mut status,
			genesis_hash.as_ptr(),
			genesis_hash.len() as u32,
			nonce_bytes.as_ptr(),
			nonce_bytes.len() as u32,
			w_url.as_ptr(),
			w_url.len() as u32,
			unchecked_extrinsic.as_mut_ptr(),
			unchecked_extrinsic_size as u32
		)
	};

	if result != sgs_status_t::SGX_SUCCESS {
		return Err("RA not successfull");
	}

	info!("RA works");
}
