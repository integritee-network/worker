use sgx_types::*;
use enclave_api::*;
use utils;
use log::*;
use std::str;
use primitive_types::U256;
use parity_codec::Encode;
use wasm::SgxWasmAction;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use crypto::rsgx_sha256_slice;

use tests::commons::*;

pub fn get_counter_works(eid: sgx_enclave_id_t) {

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

pub fn call_counter_wasm_works(eid: sgx_enclave_id_t) {

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

	let module = include_bytes!("../../../bin/worker_enclave.compact.wasm").to_vec();
	let wasm_hash = rsgx_sha256_slice(&module).unwrap();
	let wasm_hash_str = serde_json::to_string(&wasm_hash).unwrap();

	// prepare the request
	let req = SgxWasmAction::Call {
		module: Some(module),
		function: "update_counter".to_string(),
	};
	debug!("Request for WASM = {:?}", req);
	let req_str = serde_json::to_string(&req).unwrap();

	let unchecked_extrinsic_size = 500;
	let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let genesis_hash: [u8; 32] = [0; 32];

	let result = unsafe {
		call_counter_wasm(eid,
						  &mut retval,
						  req_str.as_ptr() as *const u8,
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
