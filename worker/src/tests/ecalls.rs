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

use crypto::rsgx_sha256_slice;
use enclave_api::*;
use log::*;
use parity_codec::Encode;
use primitive_types::U256;
use sgx_types::*;
use tests::commons::*;
use wasm::SgxWasmAction;

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
	evaluate_result(result);
}

pub fn call_counter_wasm_works(eid: sgx_enclave_id_t) {

	let mut retval = sgx_status_t::SGX_SUCCESS;

	let mut payload_encrypted = get_encrypted_msg(eid);
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
	let nonce_bytes = U256::encode(&U256::from("1"));
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

	evaluate_result(result);
}
