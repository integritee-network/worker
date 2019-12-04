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

use codec::Encode;
use log::*;
use sgx_types::*;
use std::fs;
use substrate_api_client::{Api, extrinsic::xt_primitives::GenericAddress,
	utils::hexstr_to_u256};
use primitives::{crypto::AccountId32, ed25519};

use crate::tests::commons::*;
use crate::constants::*;
use crate::enclave_api::*;
use crate::enclave_wrappers::*;

pub fn perform_ra_works(eid: sgx_enclave_id_t, port: &str) {
	// start the substrate-api-client to communicate with the node
	let api = Api::<ed25519::Pair>::new(format!("ws://127.0.0.1:{}", port));

	let w_url = "ws://127.0.0.1:2001";
	let genesis_hash = api.genesis_hash.as_bytes().to_vec();

	// get the public signing key of the TEE
	let mut key = [0; 32];
	let ecc_key = fs::read(ECC_PUB_KEY).expect("Unable to open ECC public key file");
	key.copy_from_slice(&ecc_key[..]);
	debug!("[+] Got ECC public key of TEE = {:?}", key);

	// get enclaves's account nonce
	let result_str = api.get_storage("System", "AccountNonce", Some(GenericAddress::from(AccountId32::from(key)).encode())).unwrap();
    let nonce = hexstr_to_u256(result_str).unwrap().low_u32();
    debug!("  TEE nonce is  {}", nonce);
	let nonce_bytes = nonce.encode();
	debug!("Enclave nonce = {:?}", nonce);

	// prepare the unchecked extrinsic
	// the size is determined in the enclave
	let unchecked_extrinsic_size = 5000;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];
	let mut retval = sgx_status_t::SGX_ERROR_UNEXPECTED;
	// ------------------------------------------------------------------------
	// perform a remote attestation and get an unchecked extrinsic back
	println!("*** Perform a remote attestation of the enclave");
	let result = unsafe {
		perform_ra(
			eid,
			&mut retval,
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
	evaluate_result(result);
	evaluate_result(retval);
}

pub fn process_forwarded_payload_works(eid: sgx_enclave_id_t, port: &str) {
	let payload_encrypted = get_encrypted_msg(eid);
	process_request(eid, payload_encrypted, port);
}
