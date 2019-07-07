use sgx_types::*;
use enclave_api::*;
use log::*;
use constants::*;
use substrate_api_client::Api;
use std::fs;
use primitive_types::U256;
use enclave_wrappers::get_account_nonce;
use parity_codec::Encode;

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
