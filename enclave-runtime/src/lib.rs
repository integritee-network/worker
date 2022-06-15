/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![feature(trait_alias)]
#![crate_name = "enclave_runtime"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(not(feature = "test"))]
use sgx_types::size_t;

use crate::{
	error::{Error, Result},
	global_components::{
		GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::worker_api_direct::sidechain_io_handler,
	utils::{hash_from_slice, utf8_str_from_raw, DecodeRaw},
};
use codec::{alloc::string::String, Decode, Encode};
use ita_stf::{Getter, ShardIdentifier, Stf};
use itc_parentchain::block_import_dispatcher::{
	triggered_dispatcher::TriggerParentchainBlockImport, DispatchBlockImport,
};
use itp_block_import_queue::PushToBlockQueue;
use itp_component_container::ComponentGetter;
use itp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::node::{
	REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION, RUNTIME_TRANSACTION_VERSION, TEEREX_MODULE,
};
use itp_sgx_crypto::{ed25519, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io as io;
use itp_sgx_io::StaticSealedIO;
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::{
	light_client_init_params::LightClientInitParams, Header, ParentchainExtrinsicParams,
	ParentchainExtrinsicParamsBuilder, SignedBlock,
};
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::crypto::Pair;
use std::{boxed::Box, slice, vec::Vec};
use substrate_api_client::{compose_extrinsic_offline, ExtrinsicParams};

mod attestation;
mod global_components;
mod initialization;
mod ipfs;
mod ocall;
mod utils;

pub mod cert;
pub mod error;
pub mod rpc;
mod sync;
mod tls_ra;
pub mod top_pool_execution;

#[cfg(feature = "test")]
pub mod test;

// this is a 'dummy' for production mode
#[cfg(not(feature = "test"))]
#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	unreachable!("Tests are not available when compiled in production mode.")
}

pub const CERTEXPIRYDAYS: i64 = 90i64;

pub type Hash = sp_core::H256;
pub type AuthorityPair = sp_core::ed25519::Pair;

#[no_mangle]
pub unsafe extern "C" fn init(
	mu_ra_addr: *const u8,
	mu_ra_addr_size: u32,
	untrusted_worker_addr: *const u8,
	untrusted_worker_addr_size: u32,
) -> sgx_status_t {
	let mu_ra_url =
		match String::decode(&mut slice::from_raw_parts(mu_ra_addr, mu_ra_addr_size as usize))
			.map_err(Error::Codec)
		{
			Ok(addr) => addr,
			Err(e) => return e.into(),
		};

	let untrusted_worker_url = match String::decode(&mut slice::from_raw_parts(
		untrusted_worker_addr,
		untrusted_worker_addr_size as usize,
	))
	.map_err(Error::Codec)
	{
		Ok(addr) => addr,
		Err(e) => return e.into(),
	};

	match initialization::init_enclave(mu_ra_url, untrusted_worker_url) {
		Err(e) => e.into(),
		Ok(()) => sgx_status_t::SGX_SUCCESS,
	}
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
	pubkey: *mut u8,
	pubkey_size: u32,
) -> sgx_status_t {
	let rsa_pubkey = match Rsa3072Seal::unseal_pubkey() {
		Ok(key) => key,
		Err(e) => return e.into(),
	};

	let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
		Ok(k) => k,
		Err(x) => {
			println!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);

	if let Err(e) =
		write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec())
	{
		return Error::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let signer = match Ed25519Seal::unseal_from_static_file().map_err(Error::Crypto) {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer.public());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_nonce(nonce: *const u32) -> sgx_status_t {
	log::info!("[Ecall Set Nonce] Setting the nonce of the enclave to: {}", *nonce);

	let mut nonce_lock = match GLOBAL_NONCE_CACHE.load_for_mutation() {
		Ok(l) => l,
		Err(e) => {
			error!("Failed to set nonce in enclave: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	*nonce_lock = Nonce(*nonce);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn mock_register_enclave_xt(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	_nonce: *const u32,
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	let genesis_hash = hash_from_slice(genesis_hash_slice);

	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url: String = Decode::decode(&mut url_slice).unwrap();
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let mre = OcallApi
		.get_mrenclave_of_self()
		.map_or_else(|_| Vec::<u8>::new(), |m| m.m.encode());

	let signer = Ed25519Seal::unseal_from_static_file().unwrap();
	let call = ([TEEREX_MODULE, REGISTER_ENCLAVE], mre, url);

	let nonce_cache = GLOBAL_NONCE_CACHE.clone();
	let mut nonce_lock = nonce_cache.load_for_mutation().expect("Nonce lock poisoning");
	let nonce_value = nonce_lock.0;

	let extrinsic_params = ParentchainExtrinsicParams::new(
		RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION,
		nonce_value,
		genesis_hash,
		ParentchainExtrinsicParamsBuilder::default(),
	);
	let xt = compose_extrinsic_offline!(signer, call, extrinsic_params).encode();

	*nonce_lock = Nonce(nonce_value + 1);
	std::mem::drop(nonce_lock);

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, xt) {
		return Error::Other(Box::new(e)).into()
	};
	sgx_status_t::SGX_SUCCESS
}

/// This is reduced to the sidechain block import RPC interface (i.e. worker-worker communication).
/// The entire rest of the RPC server is run inside the enclave and does not use this e-call function anymore.
#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
	request: *const u8,
	request_len: u32,
	response: *mut u8,
	response_len: u32,
) -> sgx_status_t {
	let request = match utf8_str_from_raw(request, request_len as usize) {
		Ok(req) => req,
		Err(e) => {
			error!("[SidechainRpc] FFI: Invalid utf8 request: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let res = match sidechain_rpc_int(request) {
		Ok(res) => res,
		Err(e) => {
			error!("RPC request failed: {:?}", e);
			return e.into()
		},
	};

	let response_slice = slice::from_raw_parts_mut(response, response_len as usize);
	if let Err(e) = write_slice_and_whitespace_pad(response_slice, res.into_bytes()) {
		return Error::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

fn sidechain_rpc_int(request: &str) -> Result<String> {
	let sidechain_block_import_queue = GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.get()?;

	let io = sidechain_io_handler(move |signed_block| {
		sidechain_block_import_queue.push_single(signed_block)
	});

	// note: errors are still returned as Option<String>
	Ok(io
		.handle_request_sync(request)
		.unwrap_or_else(|| format!("Empty rpc response for request: {}", request)))
}

#[no_mangle]
pub unsafe extern "C" fn get_state(
	trusted_op: *const u8,
	trusted_op_size: u32,
	shard: *const u8,
	shard_size: u32,
	value: *mut u8,
	value_size: u32,
) -> sgx_status_t {
	let shard = ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));
	let mut trusted_op_slice = slice::from_raw_parts(trusted_op, trusted_op_size as usize);
	let value_slice = slice::from_raw_parts_mut(value, value_size as usize);
	let getter = match Getter::decode(&mut trusted_op_slice).map_err(Error::Codec) {
		Err(e) => {
			error!("Failed to decode getter: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(g) => g,
	};

	if let Getter::trusted(trusted_getter_signed) = getter.clone() {
		debug!("verifying signature of TrustedGetterSigned");
		if let false = trusted_getter_signed.verify_signature() {
			error!("bad signature");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		}
	}

	let state_handler = match GLOBAL_STATE_HANDLER_COMPONENT.get() {
		Ok(a) => a,
		Err(e) => {
			error!("Failed to retrieve global state handler component: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let mut state = match state_handler.load(&shard) {
		Ok(s) => s,
		Err(e) => return Error::StfStateHandler(e).into(),
	};

	debug!("calling into STF to get state");
	let value_opt = Stf::get_state(&mut state, getter);

	debug!("returning getter result");
	if let Err(e) = write_slice_and_whitespace_pad(value_slice, value_opt.encode()) {
		return Error::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

/// Initialize sidechain enclave components.
///
/// Call this once at startup. Has to be called AFTER the light-client
/// (parentchain components) have been initialized (because we need the parentchain
/// block import dispatcher).
#[no_mangle]
pub unsafe extern "C" fn init_enclave_sidechain_components() -> sgx_status_t {
	if let Err(e) = initialization::init_enclave_sidechain_components() {
		error!("Failed to initialize sidechain components: {:?}", e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

/// Call this once at worker startup to initialize the TOP pool and direct invocation RPC server.
///
/// This function will run the RPC server on the same thread as it is called and will loop there.
/// That means that this function will not return as long as the RPC server is running. The calling
/// code should therefore spawn a new thread when calling this function.
#[no_mangle]
pub unsafe extern "C" fn init_direct_invocation_server(
	server_addr: *const u8,
	server_addr_size: usize,
) -> sgx_status_t {
	let mut server_addr_encoded = slice::from_raw_parts(server_addr, server_addr_size);

	let server_addr = match String::decode(&mut server_addr_encoded) {
		Ok(s) => s,
		Err(e) => {
			error!("Decoding RPC server address failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	if let Err(e) = initialization::init_direct_invocation_server(server_addr) {
		error!("Failed to initialize direct invocation server: {:?}", e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_light_client(
	params: *const u8,
	params_size: usize,
	latest_header: *mut u8,
	latest_header_size: usize,
) -> sgx_status_t {
	info!("Initializing light client!");

	let mut params = slice::from_raw_parts(params, params_size);
	let latest_header_slice = slice::from_raw_parts_mut(latest_header, latest_header_size);

	let params = match LightClientInitParams::<Header>::decode(&mut params) {
		Ok(p) => p,
		Err(e) => return Error::Codec(e).into(),
	};

	let latest_header = match initialization::init_light_client(params) {
		Ok(h) => h,
		Err(e) => return e.into(),
	};

	if let Err(e) = write_slice_and_whitespace_pad(latest_header_slice, latest_header.encode()) {
		return Error::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_shard(shard: *const u8, shard_size: u32) -> sgx_status_t {
	let shard_identifier =
		ShardIdentifier::from_slice(slice::from_raw_parts(shard, shard_size as usize));

	if let Err(e) = initialization::init_shard(shard_identifier) {
		error!("Failed to initialize shard ({:?}): {:?}", shard_identifier, e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn sync_parentchain(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	_nonce: *const u32,
) -> sgx_status_t {
	let blocks_to_sync = match Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size) {
		Ok(blocks) => blocks,
		Err(e) => return Error::Codec(e).into(),
	};

	if let Err(e) = sync_parentchain_internal(blocks_to_sync) {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`sync_parentchain`] function to be able to use the handy `?` operator.
///
/// Sync parentchain blocks to the light-client:
/// * iterates over parentchain blocks and scans for relevant extrinsics
/// * validates and execute those extrinsics (containing indirect calls), mutating state
/// * sends `confirm_call` xt's of the executed unshielding calls
/// * sends `confirm_blocks` xt's for every synced parentchain block
fn sync_parentchain_internal(blocks_to_sync: Vec<SignedBlock>) -> Result<()> {
	let block_import_dispatcher = GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT.get()?;

	block_import_dispatcher.dispatch_import(blocks_to_sync).map_err(|e| e.into())
}

/// Triggers the import of parentchain blocks when using a queue to sync parentchain block import
/// with sidechain block production.
///
/// This trigger is only useful in combination with a `TriggeredDispatcher` and sidechain. In case no
/// sidechain and the `ImmediateDispatcher` are used, this function is obsolete.
#[no_mangle]
pub unsafe extern "C" fn trigger_parentchain_block_import() -> sgx_status_t {
	match GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT.get() {
		Ok(dispatcher) => match dispatcher.import_all() {
			Ok(_) => sgx_status_t::SGX_SUCCESS,
			Err(e) => {
				error!("Failed to trigger import of parentchain blocks: {:?}", e);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		},
		Err(e) => Error::ComponentContainer(e).into(),
	}
}
