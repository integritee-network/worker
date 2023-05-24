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

use crate::{
	error::{Error, Result},
	initialization::global_components::{
		GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT, GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT, GLOBAL_STATE_HANDLER_COMPONENT,
	},
	rpc::worker_api_direct::sidechain_io_handler,
	utils::{
		get_node_metadata_repository_from_solo_or_parachain,
		get_triggered_dispatcher_from_solo_or_parachain, utf8_str_from_raw, DecodeRaw,
	},
};
use codec::{alloc::string::String, Decode};
use itc_parentchain::block_import_dispatcher::{
	triggered_dispatcher::TriggerParentchainBlockImport, DispatchBlockImport,
};
use itp_component_container::ComponentGetter;
use itp_import_queue::PushToQueue;
use itp_node_api::metadata::NodeMetadata;
use itp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider};
use itp_sgx_crypto::{ed25519, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io::StaticSealedIO;
use itp_storage::{StorageProof, StorageProofChecker};
use itp_types::{ShardIdentifier, SignedBlock};
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::sgx_status_t;
use sp_core::crypto::Pair;
use sp_runtime::traits::BlakeTwo256;
use std::{boxed::Box, slice, vec::Vec};

mod attestation;
mod empty_impls;
mod initialization;
mod ipfs;
mod ocall;
mod utils;

pub mod error;
pub mod rpc;
mod sync;
mod tls_ra;
pub mod top_pool_execution;

#[cfg(feature = "teeracle")]
pub mod teeracle;

#[cfg(feature = "test")]
pub mod test;

pub type Hash = sp_core::H256;
pub type AuthorityPair = sp_core::ed25519::Pair;

/// Initialize the enclave.
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
pub unsafe extern "C" fn set_node_metadata(
	node_metadata: *const u8,
	node_metadata_size: u32,
) -> sgx_status_t {
	let mut node_metadata_slice = slice::from_raw_parts(node_metadata, node_metadata_size as usize);
	let metadata = match NodeMetadata::decode(&mut node_metadata_slice).map_err(Error::Codec) {
		Err(e) => {
			error!("Failed to decode node metadata: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	let node_metadata_repository = match get_node_metadata_repository_from_solo_or_parachain() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	node_metadata_repository.set_metadata(metadata);
	info!("Successfully set the node meta data");

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
pub unsafe extern "C" fn init_parentchain_components(
	params: *const u8,
	params_size: usize,
	latest_header: *mut u8,
	latest_header_size: usize,
) -> sgx_status_t {
	info!("Initializing light client!");

	let encoded_params = slice::from_raw_parts(params, params_size);
	let latest_header_slice = slice::from_raw_parts_mut(latest_header, latest_header_size);

	let encoded_latest_header = match initialization::parentchain::init_parentchain_components::<
		WorkerModeProvider,
	>(encoded_params.to_vec())
	{
		Ok(h) => h,
		Err(e) => return e.into(),
	};

	if let Err(e) = write_slice_and_whitespace_pad(latest_header_slice, encoded_latest_header) {
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
	events_to_sync: *const u8,
	events_to_sync_size: usize,
	events_proofs_to_sync: *const u8,
	events_proofs_to_sync_size: usize,
	_nonce: *const u32,
) -> sgx_status_t {
	let blocks_to_sync = match Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size) {
		Ok(blocks) => blocks,
		Err(e) => return Error::Codec(e).into(),
	};

	let events_proofs_to_sync =
		match Vec::<StorageProof>::decode_raw(events_proofs_to_sync, events_proofs_to_sync_size) {
			Ok(events_proofs) => events_proofs,
			Err(e) => return Error::Codec(e).into(),
		};

	let blocks_to_sync_merkle_roots: Vec<sp_core::H256> =
		blocks_to_sync.iter().map(|block| block.block.header.state_root).collect();

	if let Err(e) = validate_events(&events_proofs_to_sync, &blocks_to_sync_merkle_roots) {
		return e.into()
	}

	let events_to_sync = match Vec::<Vec<u8>>::decode_raw(events_to_sync, events_to_sync_size) {
		Ok(events) => events,
		Err(e) => return Error::Codec(e).into(),
	};

	if let Err(e) =
		dispatch_parentchain_blocks_for_import::<WorkerModeProvider>(blocks_to_sync, events_to_sync)
	{
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Dispatch the parentchain blocks for import.
/// Depending on the worker mode, a different dispatcher is used:
///
/// * An immediate dispatcher will immediately import any parentchain blocks and execute
///   the corresponding extrinsics (offchain-worker executor).
/// * The sidechain uses a triggered dispatcher, where the import of a parentchain block is
///   synchronized and triggered by the sidechain block production cycle.
///
fn dispatch_parentchain_blocks_for_import<WorkerModeProvider: ProvideWorkerMode>(
	blocks_to_sync: Vec<SignedBlock>,
	events_to_sync: Vec<Vec<u8>>,
) -> Result<()> {
	if WorkerModeProvider::worker_mode() == WorkerMode::Teeracle {
		trace!("Not importing any parentchain blocks");
		return Ok(())
	}

	let import_dispatcher =
		if let Ok(solochain_handler) = GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.get() {
			solochain_handler.import_dispatcher.clone()
		} else if let Ok(parachain_handler) = GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT.get() {
			parachain_handler.import_dispatcher.clone()
		} else {
			return Err(Error::NoParentchainAssigned)
		};

	import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
	Ok(())
}

/// Validates the events coming from the parentchain
fn validate_events(
	events_proofs: &Vec<StorageProof>,
	blocks_merkle_roots: &Vec<sp_core::H256>,
) -> Result<()> {
	info!(
		"Validating events, events_proofs_length: {:?}, blocks_merkle_roots_lengths: {:?}",
		events_proofs.len(),
		blocks_merkle_roots.len()
	);

	if events_proofs.len() != blocks_merkle_roots.len() {
		return Err(Error::ParentChainSync)
	}

	let events_key = itp_storage::storage_value_key("System", "Events");

	let validated_events: Result<Vec<Vec<u8>>> = events_proofs
		.iter()
		.zip(blocks_merkle_roots.iter())
		.map(|(proof, root)| {
			StorageProofChecker::<BlakeTwo256>::check_proof(
				*root,
				events_key.as_slice(),
				proof.clone(),
			)
			.ok()
			.flatten()
			.ok_or_else(|| Error::ParentChainValidation(itp_storage::Error::WrongValue))
		})
		.collect();

	let _ = validated_events?;

	Ok(())
}

/// Triggers the import of parentchain blocks when using a queue to sync parentchain block import
/// with sidechain block production.
///
/// This trigger is only useful in combination with a `TriggeredDispatcher` and sidechain. In case no
/// sidechain and the `ImmediateDispatcher` are used, this function is obsolete.
#[no_mangle]
pub unsafe extern "C" fn trigger_parentchain_block_import() -> sgx_status_t {
	match internal_trigger_parentchain_block_import() {
		Ok(()) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("Failed to trigger import of parentchain blocks: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}

fn internal_trigger_parentchain_block_import() -> Result<()> {
	let triggered_import_dispatcher = get_triggered_dispatcher_from_solo_or_parachain()?;
	triggered_import_dispatcher.import_all()?;
	Ok(())
}

// This is required, because `ring` / `ring-xous` would not compile without it non-release (debug) mode.
// See #1200 for more details.
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn __assert_fail(
	__assertion: *const u8,
	__file: *const u8,
	__line: u32,
	__function: *const u8,
) -> ! {
	use core::intrinsics::abort;
	abort()
}
