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

use std::str;
use std::fs::{self, File};
use log::*;
use sgx_types::*;
use sgx_crypto_helper::rsa3072::{Rsa3072PubKey};
use constants::*;
use enclave_api::*;
use init_enclave::init_enclave;

use primitives::{ed25519, sr25519};
use primitives::crypto::Ss58Codec;

use substrate_api_client::{Api, extrinsic::xt_primitives::GenericAddress,
	utils::hexstr_to_u256};
use my_node_runtime::{UncheckedExtrinsic, Call, SubstraTEERegistryCall};
use codec::{Decode, Encode};
use primitive_types::U256;

use crypto::*;

use runtime_primitives::{AnySignature, traits::Verify};

type AccountId = <AnySignature as Verify>::Signer;

// FIXME: most of these functions use redundant code with is provided by substrate-api-client
// but first resolve this: https://github.com/scs/substrate-api-client/issues/27

pub fn get_signing_key_tee() {
	println!();
	println!("*** Start the enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	// request the key
	println!();
	println!("*** Ask the signing key from the TEE");
	let pubkey_size = 32;
	let mut pubkey = [0u8; 32];

	let mut status = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_ecc_signing_pubkey(enclave.geteid(),
							   &mut status,
							   pubkey.as_mut_ptr(),
							   pubkey_size
		)
	};

	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		error!("[-] ECALL Enclave Failed {} / status {}!", result.as_str(), status.as_str());
		return;
	}

	println!("[+] Signing key: {:?}", pubkey);

	println!();
	println!("*** Write the ECC signing key to a file");
	match fs::write(ECC_PUB_KEY, pubkey) {
		Err(x) => { error!("[-] Failed to write '{}'. {}", ECC_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", ECC_PUB_KEY); }
	}

}

pub fn get_public_key_tee()
{
	println!();
	println!("*** Start the enclave");
	let enclave = match init_enclave() {
		Ok(r) => {
			println!("[+] Init Enclave Successful. EID = {}!", r.geteid());
			r
		},
		Err(x) => {
			error!("[-] Init Enclave Failed {}!", x);
			return;
		},
	};

	// request the key
	println!();
	println!("*** Ask the public key from the TEE");
	let pubkey_size = 8192;
	let mut pubkey = vec![0u8; pubkey_size as usize];

	let mut status = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_rsa_encryption_pubkey(enclave.geteid(),
								  &mut status,
								  pubkey.as_mut_ptr(),
								  pubkey_size
		)
	};

	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		error!("[-] ECALL Enclave Failed {} / status {}!", result.as_str(), status.as_str());
		return;
	}

	let rsa_pubkey: Rsa3072PubKey = serde_json::from_slice(&pubkey[..]).unwrap();
	println!("[+] {:?}", rsa_pubkey);

	println!();
	println!("*** Write the RSA3072 public key to a file");

	let file = File::create(RSA_PUB_KEY).unwrap();
	match serde_json::to_writer(file, &rsa_pubkey) {
		Err(x) => { error!("[-] Failed to write '{}'. {}", RSA_PUB_KEY, x); },
		_      => { println!("[+] File '{}' written successfully", RSA_PUB_KEY); }
	}
}

pub fn process_request(
		eid: sgx_enclave_id_t,
		request: Vec<u8>,
		node_url: &str
) {

	// new api client (the other on is busy listening to events)
	let mut _api = Api::new(format!("ws://{}", node_url));
	let mut status = sgx_status_t::SGX_SUCCESS;
	// FIXME: refactor to function
	println!("*** Ask the signing key from the TEE");
	let tee_pubkey_size = 32;
	let mut tee_pubkey = [0u8; 32];

	let mut status = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		get_ecc_signing_pubkey(eid,
							   &mut status,
							   tee_pubkey.as_mut_ptr(),
							   tee_pubkey_size
		)
	};
	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		error!("[-] ECALL Enclave Failed {} / status {}!", result.as_str(), status.as_str());
		return;
	}

	// Attention: this HAS to be sr25519, although its a ed25519 key!
	let tee_public = sr25519::Public::from_raw(tee_pubkey);
	info!("[+] Got ed25519 account of TEE = {}", tee_public.to_ss58check());
	let tee_accountid = AccountId::from(tee_public);

	let result_str = _api.get_storage("System", "AccountNonce", Some(tee_accountid.encode())).unwrap();

	let genesis_hash = _api.genesis_hash.as_bytes().to_vec();

	let nonce = hexstr_to_u256(result_str).unwrap().low_u32();	
	info!("Enclave nonce = {:?}", nonce);
	let nonce_bytes = nonce.encode();

	let unchecked_extrinsic_size = 500;
	let mut unchecked_extrinsic : Vec<u8> = vec![0u8; unchecked_extrinsic_size as usize];

	let result = unsafe {
		execute_stf(eid,
					&mut status,
					request.to_vec().as_mut_ptr(),
					request.len() as u32,
					genesis_hash.as_ptr(),
					genesis_hash.len() as u32,
					nonce_bytes.as_ptr(),
					nonce_bytes.len() as u32,
					unchecked_extrinsic.as_mut_ptr(),
					unchecked_extrinsic_size as u32
		)
	};
	if result != sgx_status_t::SGX_SUCCESS || status != sgx_status_t::SGX_SUCCESS {
		error!("[-] ECALL Enclave Failed {} / status {}!", result.as_str(), status.as_str());
		return;
	}

	println!("[<] Message decoded and processed in the enclave");
	let ue = UncheckedExtrinsic::decode(&mut unchecked_extrinsic.as_slice()).unwrap();
	let mut _xthex = hex::encode(ue.encode());
	_xthex.insert_str(0, "0x");
	println!("[>] Confirm processing (send the extrinsic)");
	let tx_hash = _api.send_extrinsic(_xthex).unwrap();
	println!("[<] Extrinsic got finalized. Hash: {:?}\n", tx_hash);

}