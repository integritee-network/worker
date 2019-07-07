use sgx_types::*;
use enclave_api::*;
use utils;
use wasm::sgx_enclave_wasm_init;
use init_enclave::init_enclave;
use log::*;
use constants::*;
use substrate_api_client::Api;
use std::fs;
use std::str;
use primitive_types::U256;
use enclave_wrappers::get_account_nonce;
use parity_codec::Encode;
use wasm::SgxWasmAction;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use crypto::rsgx_sha256_slice;

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

	if result != sgx_status_t::SGX_SUCCESS {
		error!("RA not successfull");
	}

	info!("RA works");
}

fn call_counter_wasm_works(eid: sgx_enclave_id_t) {

	// ---------------------------------------------------------
	// Mock Client Actions
	// ---------------------------------------------------------
	let hash: Vec<String> = utils::get_wasm_hash();
	println!("Wasm Hash: {:?}", hash[0]);
	println!("Wasm Binary : {:?}", hash[1]);

	let sha = hex::decode(hash[0].clone()).unwrap();
	let sha256: sgx_sha256_hash_t = from_slice(&sha);


	let pubkey_size = 8192;
	let mut pubkey = vec![0u8; pubkey_size as usize];

	let mut retval = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_rsa_encryption_pubkey(eid,
								  &mut retval,
								  pubkey.as_mut_ptr(),
								  pubkey_size
		);
	};


	let rsa_pubkey: Rsa3072PubKey = serde_json::from_str(str::from_utf8(&pubkey[..]).unwrap()).unwrap();

	let account: String = "Alice".to_string();
	let amount = 42;
	let nonce_bytes = U256::encode(&U256::from("1"));

	let message = Message { account, amount, sha256 };
	let plaintext = serde_json::to_vec(&message).unwrap();
	let mut payload_encrypted: Vec<u8> = Vec::new();
	rsa_pubkey.encrypt_buffer(&plaintext, &mut payload_encrypted).unwrap();

	// ------------------------------------------------------------------------
	// Worker Actions
	// ------------------------------------------------------------------------

	let module = include_bytes!("../../bin/worker_enclave.compact.wasm").to_vec();
	let wasm_hash = rsgx_sha256_slice(&module).unwrap();
	let wasm_hash_str = serde_json::to_string(&wasm_hash).unwrap();

	// prepare the request
	let req = SgxWasmAction::Call {
		module : Some(module),
		function  : "update_counter".to_string(),
	};
	debug!("Request for WASM = {:?}", req);
	let req_str = serde_json::to_string(&req).unwrap();

	let unchecked_extrinsic_size = 500;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let genesis_hash: [u8; 32] = [0; 32];

	let result = unsafe {
		call_counter_wasm(eid,
						  &mut retval,
						  req_str.as_ptr() as * const u8,
						  req_str.len(),
						  payload_encrypted.as_mut_ptr(),
						  payload_encrypted.len() as u32,
						  genesis_hash.as_ptr(),
						  genesis_hash.len() as u32,
						  nonce_bytes.as_ptr(),
						  nonce_bytes.len() as u32,
						  wasm_hash_str.as_ptr(),
						  wasm_hash_str.len() as u32,
						  unchecked_extrinsic.as_mut_ptr(),
						  unchecked_extrinsic_size as u32
		)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {
			println!("[<] Message decoded and processed in the enclave");
		},
		_ => {
			error!("[<] Error processing message in the enclave");
			panic!("");
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
	account: String,
	amount: u32,
	sha256: sgx_sha256_hash_t
}

pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
	let mut array = [0; 32];
	let bytes = &bytes[..array.len()]; // panics if not enough data
	array.copy_from_slice(bytes);
	array
}
