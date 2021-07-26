/*
	Copyright 2019 Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::{error::Error, Enclave, EnclaveResult};
use codec::{Decode, Encode};
use frame_support::ensure;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sgx_types::*;
use sp_core::ed25519;
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::traits::Header;
use substratee_enclave_api_ffi as ffi;
use substratee_settings::worker::{
	HEADER_MAX_SIZE, MR_ENCLAVE_SIZE, SHIELDING_KEY_SIZE, SIGNING_KEY_SIZE, STATE_VALUE_MAX_SIZE,
};

/// Trait for base/common Enclave API functions
pub trait EnclaveBase: Send + Sync + 'static {
	/// initialize the enclave (needs to be called once at application startup)
	fn init(&self) -> EnclaveResult<()>;

	/// initialize the chain relay (needs to be called once at application startup)
	fn init_chain_relay<SpHeader: Header>(
		&self,
		genesis_header: SpHeader,
		authority_list: VersionedAuthorityList,
		authority_proof: Vec<Vec<u8>>,
	) -> EnclaveResult<SpHeader>;

	fn get_state(&self, cyphertext: Vec<u8>, shard: Vec<u8>) -> EnclaveResult<Vec<u8>>;

	fn get_rsa_shielding_pubkey(&self) -> EnclaveResult<Rsa3072PubKey>;

	fn get_ecc_signing_pubkey(&self) -> EnclaveResult<ed25519::Public>;

	fn get_mrenclave(&self) -> EnclaveResult<[u8; MR_ENCLAVE_SIZE]>;
}

/// EnclaveApi implementation for Enclave struct
impl EnclaveBase for Enclave {
	fn init(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe { ffi::init(self.eid, &mut retval) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}

	fn init_chain_relay<SpHeader: Header>(
		&self,
		genesis_header: SpHeader,
		authority_list: VersionedAuthorityList,
		authority_proof: Vec<Vec<u8>>,
	) -> EnclaveResult<SpHeader> {
		let encoded_genesis_header = genesis_header.encode();
		let authority_proof_encoded = authority_proof.encode();

		// Todo: this is a bit ugly but the common `encode()` is not implemented for authority list
		let latest_header_encoded = authority_list.using_encoded(|authorities| {
			init_chain_relay_ffi(
				self.eid,
				authorities.to_vec(),
				encoded_genesis_header,
				authority_proof_encoded,
			)
		})?;

		let latest: SpHeader = Decode::decode(&mut latest_header_encoded.as_slice()).unwrap();
		info!("Latest Header {:?}", latest);

		Ok(latest)
	}

	fn get_state(&self, cyphertext: Vec<u8>, shard: Vec<u8>) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let value_size = STATE_VALUE_MAX_SIZE;
		let mut value = vec![0u8; value_size as usize];

		let result = unsafe {
			ffi::get_state(
				self.eid,
				&mut retval,
				cyphertext.as_ptr(),
				cyphertext.len() as u32,
				shard.as_ptr(),
				shard.len() as u32,
				value.as_mut_ptr(),
				value.len() as u32,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(value)
	}

	fn get_rsa_shielding_pubkey(&self) -> EnclaveResult<Rsa3072PubKey> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let pubkey_size = SHIELDING_KEY_SIZE;
		let mut pubkey = vec![0u8; pubkey_size as usize];

		let result = unsafe {
			ffi::get_rsa_encryption_pubkey(
				self.eid,
				&mut retval,
				pubkey.as_mut_ptr(),
				pubkey.len() as u32,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		let rsa_pubkey: Rsa3072PubKey = serde_json::from_slice(pubkey.as_slice()).unwrap();
		debug!("got RSA pubkey {:?}", rsa_pubkey);
		Ok(rsa_pubkey)
	}

	fn get_ecc_signing_pubkey(&self) -> EnclaveResult<ed25519::Public> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let mut pubkey = [0u8; SIGNING_KEY_SIZE as usize];

		let result = unsafe {
			ffi::get_ecc_signing_pubkey(
				self.eid,
				&mut retval,
				pubkey.as_mut_ptr(),
				pubkey.len() as u32,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(ed25519::Public::from_raw(pubkey))
	}

	fn get_mrenclave(&self) -> EnclaveResult<[u8; MR_ENCLAVE_SIZE]> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let mut mr_enclave = [0u8; MR_ENCLAVE_SIZE as usize];

		let result = unsafe {
			ffi::get_mrenclave(
				self.eid,
				&mut retval,
				mr_enclave.as_mut_ptr(),
				mr_enclave.len() as u32,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(mr_enclave)
	}
}

fn init_chain_relay_ffi(
	enclave_id: sgx_enclave_id_t,
	authorities_vec: Vec<u8>,
	encoded_genesis_header: Vec<u8>,
	authority_proof_encoded: Vec<u8>,
) -> EnclaveResult<Vec<u8>> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let latest_header_size = HEADER_MAX_SIZE;
	let mut latest_header = vec![0u8; latest_header_size as usize];

	let result = unsafe {
		ffi::init_chain_relay(
			enclave_id,
			&mut retval,
			encoded_genesis_header.as_ptr(),
			encoded_genesis_header.len(),
			authorities_vec.as_ptr(),
			authorities_vec.len(),
			authority_proof_encoded.as_ptr(),
			authority_proof_encoded.len(),
			latest_header.as_mut_ptr(),
			latest_header.len(),
		)
	};

	ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
	ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

	Ok(latest_header)
}
