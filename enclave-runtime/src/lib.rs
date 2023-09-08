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
		GLOBAL_INTEGRITEE_PARACHAIN_HANDLER_COMPONENT, GLOBAL_INTEGRITEE_PARENTCHAIN_NONCE_CACHE,
		GLOBAL_INTEGRITEE_SOLOCHAIN_HANDLER_COMPONENT, GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT, GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT,
		GLOBAL_STATE_HANDLER_COMPONENT, GLOBAL_TARGET_A_PARACHAIN_HANDLER_COMPONENT,
		GLOBAL_TARGET_A_PARENTCHAIN_NONCE_CACHE, GLOBAL_TARGET_A_SOLOCHAIN_HANDLER_COMPONENT,
		GLOBAL_TARGET_B_PARACHAIN_HANDLER_COMPONENT, GLOBAL_TARGET_B_PARENTCHAIN_NONCE_CACHE,
		GLOBAL_TARGET_B_SOLOCHAIN_HANDLER_COMPONENT,
	},
	rpc::worker_api_direct::sidechain_io_handler,
	utils::{
		get_node_metadata_repository_from_integritee_solo_or_parachain,
		get_node_metadata_repository_from_target_a_solo_or_parachain,
		get_node_metadata_repository_from_target_b_solo_or_parachain, utf8_str_from_raw, DecodeRaw,
	},
};
use codec::Decode;
use itc_parentchain::{
	block_import_dispatcher::{
		triggered_dispatcher::TriggerParentchainBlockImport, DispatchBlockImport,
	},
	primitives::ParentchainId,
};
use itp_component_container::ComponentGetter;
use itp_import_queue::PushToQueue;
use itp_node_api::metadata::NodeMetadata;
use itp_nonce_cache::{MutateNonce, Nonce};
use itp_settings::worker_mode::{ProvideWorkerMode, WorkerMode, WorkerModeProvider};
use itp_sgx_crypto::key_repository::AccessPubkey;
use itp_storage::{StorageProof, StorageProofChecker};
use itp_types::{ShardIdentifier, SignedBlock};
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use once_cell::sync::OnceCell;
use sgx_types::sgx_status_t;
use sp_runtime::traits::BlakeTwo256;
use std::{
	boxed::Box,
	path::PathBuf,
	slice,
	string::{String, ToString},
	vec::Vec,
};

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

static BASE_PATH: OnceCell<PathBuf> = OnceCell::new();

fn get_base_path() -> Result<PathBuf> {
	let base_path = BASE_PATH.get().ok_or_else(|| {
		Error::Other("BASE_PATH not initialized. Broken enclave init flow!".to_string().into())
	})?;

	Ok(base_path.clone())
}

/// Initialize the enclave.
#[no_mangle]
pub unsafe extern "C" fn init(
	mu_ra_addr: *const u8,
	mu_ra_addr_size: u32,
	untrusted_worker_addr: *const u8,
	untrusted_worker_addr_size: u32,
	encoded_base_dir_str: *const u8,
	encoded_base_dir_size: u32,
) -> sgx_status_t {
	// Initialize the logging environment in the enclave.
	env_logger::init();

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

	let base_dir = match String::decode(&mut slice::from_raw_parts(
		encoded_base_dir_str,
		encoded_base_dir_size as usize,
	))
	.map_err(Error::Codec)
	{
		Ok(b) => b,
		Err(e) => return e.into(),
	};

	info!("Setting base_dir to {}", base_dir);
	let path = PathBuf::from(base_dir);
	BASE_PATH.set(path.clone()).expect("We only init this once here; qed.");

	match initialization::init_enclave(mu_ra_url, untrusted_worker_url, path) {
		Err(e) => e.into(),
		Ok(()) => sgx_status_t::SGX_SUCCESS,
	}
}

#[no_mangle]
pub unsafe extern "C" fn get_rsa_encryption_pubkey(
	pubkey: *mut u8,
	pubkey_size: u32,
) -> sgx_status_t {
	let shielding_key_repository = match GLOBAL_SHIELDING_KEY_REPOSITORY_COMPONENT.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let rsa_pubkey = match shielding_key_repository.retrieve_pubkey() {
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
	let signing_key_repository = match GLOBAL_SIGNING_KEY_REPOSITORY_COMPONENT.get() {
		Ok(s) => s,
		Err(e) => {
			error!("{:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let signer_public = match signing_key_repository.retrieve_pubkey() {
		Ok(s) => s,
		Err(e) => return e.into(),
	};

	debug!("Restored ECC pubkey: {:?}", signer_public);

	let pubkey_slice = slice::from_raw_parts_mut(pubkey, pubkey_size as usize);
	pubkey_slice.clone_from_slice(&signer_public);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_nonce(
	nonce: *const u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> sgx_status_t {
	let id = match ParentchainId::decode_raw(parentchain_id, parentchain_id_size as usize) {
		Err(e) => {
			error!("Failed to decode parentchain_id: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	info!("Setting the nonce of the enclave to: {} for parentchain: {:?}", *nonce, id);

	let nonce_lock = match id {
		ParentchainId::Integritee => GLOBAL_INTEGRITEE_PARENTCHAIN_NONCE_CACHE.load_for_mutation(),
		ParentchainId::TargetA => GLOBAL_TARGET_A_PARENTCHAIN_NONCE_CACHE.load_for_mutation(),
		ParentchainId::TargetB => GLOBAL_TARGET_B_PARENTCHAIN_NONCE_CACHE.load_for_mutation(),
	};

	match nonce_lock {
		Ok(mut nonce_guard) => *nonce_guard = Nonce(*nonce),
		Err(e) => {
			error!("Failed to set {:?} parentchain nonce in enclave: {:?}", id, e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn set_node_metadata(
	node_metadata: *const u8,
	node_metadata_size: u32,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> sgx_status_t {
	let id = match ParentchainId::decode_raw(parentchain_id, parentchain_id_size as usize) {
		Err(e) => {
			error!("Failed to decode parentchain_id: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	let metadata = match NodeMetadata::decode_raw(node_metadata, node_metadata_size as usize) {
		Err(e) => {
			error!("Failed to decode node metadata: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
		Ok(m) => m,
	};

	info!("Setting node meta data for parentchain: {:?}", id);

	let node_metadata_repository = match id {
		ParentchainId::Integritee =>
			get_node_metadata_repository_from_integritee_solo_or_parachain(),
		ParentchainId::TargetA => get_node_metadata_repository_from_target_a_solo_or_parachain(),
		ParentchainId::TargetB => get_node_metadata_repository_from_target_b_solo_or_parachain(),
	};

	match node_metadata_repository {
		Ok(repo) => repo.set_metadata(metadata),
		Err(e) => {
			error!("Could not get {:?} parentchain component: {:?}", id, e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

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

	match init_parentchain_params_internal(encoded_params.to_vec(), latest_header_slice) {
		Ok(()) => sgx_status_t::SGX_SUCCESS,
		Err(e) => e.into(),
	}
}

/// Initializes the parentchain components and writes the latest header into the `latest_header` slice.
fn init_parentchain_params_internal(params: Vec<u8>, latest_header: &mut [u8]) -> Result<()> {
	use initialization::parentchain::init_parentchain_components;

	let encoded_latest_header =
		init_parentchain_components::<WorkerModeProvider>(get_base_path()?, params)?;

	write_slice_and_whitespace_pad(latest_header, encoded_latest_header)?;

	Ok(())
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
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> sgx_status_t {
	if let Err(e) = sync_parentchain_internal(
		blocks_to_sync,
		blocks_to_sync_size,
		events_to_sync,
		events_to_sync_size,
		events_proofs_to_sync,
		events_proofs_to_sync_size,
		parentchain_id,
		parentchain_id_size,
	) {
		error!("Error synching parentchain: {:?}", e);
	}

	sgx_status_t::SGX_SUCCESS
}

#[allow(clippy::too_many_arguments)]
unsafe fn sync_parentchain_internal(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	events_to_sync: *const u8,
	events_to_sync_size: usize,
	events_proofs_to_sync: *const u8,
	events_proofs_to_sync_size: usize,
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> Result<()> {
	let blocks_to_sync = Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size)?;
	let events_proofs_to_sync =
		Vec::<StorageProof>::decode_raw(events_proofs_to_sync, events_proofs_to_sync_size)?;
	let parentchain_id = ParentchainId::decode_raw(parentchain_id, parentchain_id_size as usize)?;

	let blocks_to_sync_merkle_roots: Vec<sp_core::H256> =
		blocks_to_sync.iter().map(|block| block.block.header.state_root).collect();

	if let Err(e) = validate_events(&events_proofs_to_sync, &blocks_to_sync_merkle_roots) {
		return e.into()
	}

	let events_to_sync = Vec::<Vec<u8>>::decode_raw(events_to_sync, events_to_sync_size)?;

	dispatch_parentchain_blocks_for_import::<WorkerModeProvider>(
		blocks_to_sync,
		events_to_sync,
		&parentchain_id,
	)
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
	id: &ParentchainId,
) -> Result<()> {
	if WorkerModeProvider::worker_mode() == WorkerMode::Teeracle {
		trace!("Not importing any parentchain blocks");
		return Ok(())
	}

	match id {
		ParentchainId::Integritee => {
			if let Ok(handler) = GLOBAL_INTEGRITEE_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else if let Ok(handler) = GLOBAL_INTEGRITEE_PARACHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else {
				return Err(Error::NoIntegriteeParentchainAssigned)
			};
		},
		ParentchainId::TargetA => {
			if let Ok(handler) = GLOBAL_TARGET_A_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else if let Ok(handler) = GLOBAL_TARGET_A_PARACHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else {
				return Err(Error::NoTargetAParentchainAssigned)
			};
		},
		ParentchainId::TargetB => {
			if let Ok(handler) = GLOBAL_TARGET_B_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else if let Ok(handler) = GLOBAL_TARGET_B_PARACHAIN_HANDLER_COMPONENT.get() {
				handler.import_dispatcher.dispatch_import(blocks_to_sync, events_to_sync)?;
			} else {
				return Err(Error::NoTargetBParentchainAssigned)
			};
		},
	}

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
pub unsafe extern "C" fn trigger_parentchain_block_import(
	parentchain_id: *const u8,
	parentchain_id_size: u32,
) -> sgx_status_t {
	let parentchain_id =
		match ParentchainId::decode_raw(parentchain_id, parentchain_id_size as usize) {
			Ok(id) => id,
			Err(e) => {
				error!("Could not decode parentchain id: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	match internal_trigger_parentchain_block_import(&parentchain_id) {
		Ok(()) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("Failed to trigger import of parentchain blocks: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}

fn internal_trigger_parentchain_block_import(id: &ParentchainId) -> Result<()> {
	let _maybe_latest_block = match id {
		ParentchainId::Integritee => {
			if let Ok(handler) = GLOBAL_INTEGRITEE_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else if let Ok(handler) = GLOBAL_INTEGRITEE_PARACHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else {
				return Err(Error::NoIntegriteeParentchainAssigned)
			}
		},
		ParentchainId::TargetA => {
			if let Ok(handler) = GLOBAL_TARGET_A_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else if let Ok(handler) = GLOBAL_TARGET_A_PARACHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else {
				return Err(Error::NoTargetAParentchainAssigned)
			}
		},
		ParentchainId::TargetB => {
			if let Ok(handler) = GLOBAL_TARGET_B_SOLOCHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else if let Ok(handler) = GLOBAL_TARGET_B_PARACHAIN_HANDLER_COMPONENT.get() {
				handler
					.import_dispatcher
					.triggered_dispatcher()
					.ok_or(Error::ExpectedTriggeredImportDispatcher)?
					.import_all()?
			} else {
				return Err(Error::NoTargetBParentchainAssigned)
			}
		},
	};

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
