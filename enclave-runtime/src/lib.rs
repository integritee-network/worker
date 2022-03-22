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
		EnclaveSidechainBlockImportQueue, EnclaveSidechainBlockImportQueueWorker,
		EnclaveSidechainBlockImporter, EnclaveSidechainBlockSyncer, EnclaveStfExecutor,
		EnclaveTopPoolOperationHandler, EnclaveValidatorAccessor,
		GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT, GLOBAL_RPC_AUTHOR_COMPONENT,
		GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT, GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT,
		GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT,
		GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT,
	},
	ocall::OcallApi,
	rpc::worker_api_direct::{public_api_rpc_handler, sidechain_io_handler},
	utils::{hash_from_slice, utf8_str_from_raw, write_slice_and_whitespace_pad, DecodeRaw},
};
use base58::ToBase58;
use codec::{alloc::string::String, Decode, Encode};
use ita_exchange_oracle::{coingecko::CoinGeckoClient, types::TradingPair, GetExchangeRate};
use ita_stf::{Getter, ShardIdentifier, Stf};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_parentchain::{
	block_import_dispatcher::{
		triggered_dispatcher::{TriggerParentchainBlockImport, TriggeredDispatcher},
		DispatchBlockImport,
	},
	block_importer::ParentchainBlockImporter,
	indirect_calls_executor::IndirectCallsExecutor,
	light_client::{concurrent_access::ValidatorAccess, LightClientState},
};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_block_import_queue::{BlockImportQueue, PushToBlockQueue};
use itp_component_container::{ComponentGetter, ComponentInitializer};
use itp_extrinsics_factory::{CreateExtrinsics, ExtrinsicsFactory};
use itp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_primitives_cache::GLOBAL_PRIMITIVES_CACHE;
use itp_settings::node::{
	REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION, RUNTIME_TRANSACTION_VERSION, TEERACLE_MODULE,
	TEEREX_MODULE, UPDATE_EXCHANGE_RATE,
};
use itp_sgx_crypto::{aes, ed25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal};
use itp_sgx_io as io;
use itp_sgx_io::SealedIO;
use itp_stf_executor::executor::StfExecutor;
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState, GlobalFileStateHandler,
};
use itp_storage::StorageProof;
use itp_types::{Block, Header, OpaqueCall, SignedBlock};
use its_sidechain::{
	aura::block_importer::BlockImporter, top_pool_executor::TopPoolOperationHandler,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::{crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::OpaqueExtrinsic;
use std::{slice, sync::Arc, vec::Vec};
use substrate_api_client::compose_extrinsic_offline;

mod attestation;
mod global_components;
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

#[cfg(feature = "test")]
pub mod tests;

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
	// Initialize the logging environment in the enclave.
	env_logger::init();

	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}
	let signer = match Ed25519Seal::unseal().map_err(Error::Crypto) {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	if let Err(e) = rsa3072::create_sealed_if_absent() {
		return e.into()
	}

	// Create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attastation is performed with the primary worker.
	if let Err(e) = aes::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let state_handler = GlobalFileStateHandler;

	// For debug purposes, list shards. no problem to panic if fails.
	let shards = state_handler.list_shards().unwrap();
	debug!("found the following {} shards on disk:", shards.len());
	for s in shards {
		debug!("{}", s.encode().to_base58())
	}

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

	if let Err(e) = itp_primitives_cache::set_primitives(
		GLOBAL_PRIMITIVES_CACHE.as_ref(),
		&mu_ra_url,
		&untrusted_worker_url,
	)
	.map_err(Error::PrimitivesAccess)
	{
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
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
	write_slice_and_whitespace_pad(pubkey_slice, rsa_pubkey_json.as_bytes().to_vec());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn get_ecc_signing_pubkey(pubkey: *mut u8, pubkey_size: u32) -> sgx_status_t {
	if let Err(e) = ed25519::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let signer = match Ed25519Seal::unseal().map_err(Error::Crypto) {
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

	let signer = Ed25519Seal::unseal().unwrap();
	let call = ([TEEREX_MODULE, REGISTER_ENCLAVE], mre, url);

	let nonce_cache = GLOBAL_NONCE_CACHE.clone();
	let mut nonce_lock = nonce_cache.load_for_mutation().expect("Nonce lock poisoning");
	let nonce_value = nonce_lock.0;

	let xt = compose_extrinsic_offline!(
		signer,
		call,
		nonce_value,
		Era::Immortal,
		genesis_hash,
		genesis_hash,
		RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION
	)
	.encode();

	*nonce_lock = Nonce(nonce_value + 1);
	std::mem::drop(nonce_lock);

	write_slice_and_whitespace_pad(extrinsic_slice, xt);
	sgx_status_t::SGX_SUCCESS
}

/// this is reduced to the side chain block import RPC interface (i.e. worker-worker communication)
/// the entire rest of the RPC server is run inside the enclave and does not use this e-call function anymore
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
	write_slice_and_whitespace_pad(response_slice, res.into_bytes());

	sgx_status_t::SGX_SUCCESS
}

fn sidechain_rpc_int(request: &str) -> Result<String> {
	let sidechain_block_import_queue = GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT
		.get()
		.ok_or(Error::ComponentNotInitialized)?;

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
	let getter = Getter::decode(&mut trusted_op_slice).unwrap();

	if let Getter::trusted(trusted_getter_signed) = getter.clone() {
		debug!("verifying signature of TrustedGetterSigned");
		if let false = trusted_getter_signed.verify_signature() {
			error!("bad signature");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		}
	}

	let state_handler = GlobalFileStateHandler;

	let mut state = match state_handler.load_initialized(&shard) {
		Ok(s) => s,
		Err(e) => return Error::StfStateHandler(e).into(),
	};

	debug!("calling into STF to get state");
	let value_opt = Stf::get_state(&mut state, getter);

	debug!("returning getter result");
	write_slice_and_whitespace_pad(value_slice, value_opt.encode());

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

	let watch_extractor = Arc::new(create_determine_watch::<Hash>());
	let connection_registry = Arc::new(ConnectionRegistry::<Hash, TungsteniteWsConnection>::new());

	let rsa_shielding_key = match Rsa3072Seal::unseal() {
		Ok(k) => k,
		Err(e) => {
			error!("Failed to unseal shielding key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let state_handler = Arc::new(GlobalFileStateHandler);
	let ocall_api = Arc::new(OcallApi);

	let rpc_author = its_sidechain::top_pool_rpc_author::initializer::create_top_pool_rpc_author(
		connection_registry.clone(),
		state_handler.clone(),
		ocall_api.clone(),
		rsa_shielding_key,
	);

	GLOBAL_RPC_AUTHOR_COMPONENT.initialize(rpc_author.clone());

	let stf_executor = Arc::new(EnclaveStfExecutor::new(ocall_api, state_handler));
	let top_pool_operation_handler =
		Arc::new(EnclaveTopPoolOperationHandler::new(rpc_author.clone(), stf_executor));

	GLOBAL_TOP_POOL_OPERATION_HANDLER_COMPONENT.initialize(top_pool_operation_handler);

	let io_handler = public_api_rpc_handler(rpc_author);
	let rpc_handler = Arc::new(RpcWsHandler::new(io_handler, watch_extractor, connection_registry));

	run_ws_server(server_addr.as_str(), rpc_handler);

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_light_client(
	genesis_header: *const u8,
	genesis_header_size: usize,
	authority_list: *const u8,
	authority_list_size: usize,
	authority_proof: *const u8,
	authority_proof_size: usize,
	latest_header: *mut u8,
	latest_header_size: usize,
) -> sgx_status_t {
	info!("Initializing light client!");

	let mut header = slice::from_raw_parts(genesis_header, genesis_header_size);
	let latest_header_slice = slice::from_raw_parts_mut(latest_header, latest_header_size);
	let mut auth = slice::from_raw_parts(authority_list, authority_list_size);
	let mut proof = slice::from_raw_parts(authority_proof, authority_proof_size);

	let header = match Header::decode(&mut header) {
		Ok(h) => h,
		Err(e) => {
			error!("Decoding Header failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let auth = match VersionedAuthorityList::decode(&mut auth) {
		Ok(a) => a,
		Err(e) => {
			error!("Decoding VersionedAuthorityList failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let proof = match StorageProof::decode(&mut proof) {
		Ok(h) => h,
		Err(e) => {
			error!("Decoding Header failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	match itc_parentchain::light_client::io::read_or_init_validator::<Block>(header, auth, proof) {
		Ok(header) => write_slice_and_whitespace_pad(latest_header_slice, header.encode()),
		Err(e) => return e.into(),
	}

	// Initialize the global parentchain block import dispatcher instance.
	let signer = match Ed25519Seal::unseal() {
		Ok(s) => s,
		Err(e) => {
			error!("Error retrieving signer key pair: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let shielding_key = match Rsa3072Seal::unseal() {
		Ok(s) => s,
		Err(e) => {
			error!("Error retrieving shielding key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let state_key = match AesSeal::unseal() {
		Ok(k) => k,
		Err(e) => {
			error!("Failed to unseal state key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let rpc_author = match GLOBAL_RPC_AUTHOR_COMPONENT.get() {
		Some(a) => a,
		None => {
			error!("Failed to retrieve global top pool author");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let validator_access = Arc::new(EnclaveValidatorAccessor::default());
	let genesis_hash =
		match validator_access.execute_on_validator(|v| v.genesis_hash(v.num_relays())) {
			Ok(g) => g,
			Err(e) => {
				error!("Error retrieving genesis hash: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let file_state_handler = Arc::new(GlobalFileStateHandler);
	let ocall_api = Arc::new(OcallApi);
	let stf_executor = Arc::new(StfExecutor::new(ocall_api.clone(), file_state_handler.clone()));
	let extrinsics_factory =
		Arc::new(ExtrinsicsFactory::new(genesis_hash, signer.clone(), GLOBAL_NONCE_CACHE.clone()));
	let indirect_calls_executor =
		Arc::new(IndirectCallsExecutor::new(shielding_key, stf_executor.clone()));
	let parentchain_block_importer = ParentchainBlockImporter::new(
		validator_access,
		ocall_api.clone(),
		stf_executor.clone(),
		extrinsics_factory,
		indirect_calls_executor,
	);
	let parentchain_block_import_queue = BlockImportQueue::<SignedBlock>::default();
	let parentchain_block_import_dispatcher = Arc::new(TriggeredDispatcher::new(
		parentchain_block_importer,
		parentchain_block_import_queue,
	));

	GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT
		.initialize(parentchain_block_import_dispatcher.clone());

	let top_pool_executor = Arc::<EnclaveTopPoolOperationHandler>::new(
		TopPoolOperationHandler::new(rpc_author, stf_executor),
	);
	let sidechain_block_importer = Arc::<EnclaveSidechainBlockImporter>::new(BlockImporter::new(
		file_state_handler,
		state_key,
		signer,
		top_pool_executor,
		parentchain_block_import_dispatcher,
		ocall_api.clone(),
	));

	let sidechain_block_syncer =
		Arc::new(EnclaveSidechainBlockSyncer::new(sidechain_block_importer, ocall_api));

	GLOBAL_SIDECHAIN_BLOCK_SYNCER_COMPONENT.initialize(sidechain_block_syncer.clone());

	let sidechain_block_import_queue = Arc::new(EnclaveSidechainBlockImportQueue::default());
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_COMPONENT.initialize(sidechain_block_import_queue.clone());

	let sidechain_block_import_queue_worker =
		Arc::new(EnclaveSidechainBlockImportQueueWorker::new(
			sidechain_block_import_queue,
			sidechain_block_syncer,
		));
	GLOBAL_SIDECHAIN_IMPORT_QUEUE_WORKER_COMPONENT.initialize(sidechain_block_import_queue_worker);

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
	let block_import_dispatcher = GLOBAL_PARENTCHAIN_IMPORT_DISPATCHER_COMPONENT
		.get()
		.ok_or(Error::ComponentNotInitialized)?;

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
		Some(dispatcher) => match dispatcher.import_all() {
			Ok(_) => sgx_status_t::SGX_SUCCESS,
			Err(e) => {
				error!("Failed to trigger import of parentchain blocks: {:?}", e);
				sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		},
		None => (Error::ComponentNotInitialized).into(),
	}
}

/// For now get the DOT/currency exchange rate from coingecko API.
#[no_mangle]
pub unsafe extern "C" fn update_market_data_xt(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	crypto_currency_ptr: *const u8,
	crypto_currency_size: u32,
	fiat_currency_ptr: *const u8,
	fiat_currency_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	let genesis_hash = hash_from_slice(genesis_hash_slice);

	let mut crypto_currency_slice =
		slice::from_raw_parts(crypto_currency_ptr, crypto_currency_size as usize);
	let crypto_currency: String = Decode::decode(&mut crypto_currency_slice).unwrap();

	let mut fiat_currency_slice =
		slice::from_raw_parts(fiat_currency_ptr, fiat_currency_size as usize);
	let fiat_currency: String = Decode::decode(&mut fiat_currency_slice).unwrap();

	let extrinsics = match update_market_data_internal(genesis_hash, crypto_currency, fiat_currency)
	{
		Ok(xts) => xts,
		Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	// Only one extrinsic to send over the node api directly.
	let extrinsic = match extrinsics.get(0) {
		Some(xt) => xt,
		None => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	// Save created extrinsic as slice in the return value unchecked_extrinsic.
	write_slice_and_whitespace_pad(extrinsic_slice, extrinsic.encode());
	sgx_status_t::SGX_SUCCESS
}

fn update_market_data_internal(
	genesis_hash: H256,
	crypto_currency: String,
	fiat_currency: String,
) -> Result<Vec<OpaqueExtrinsic>> {
	type ExchangeRateClient = CoinGeckoClient<OcallApi>;

	let signer = Ed25519Seal::unseal()?;

	let extrinsics_factory =
		ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone());

	// Get the exchange rate
	let url = match ExchangeRateClient::base_url() {
		Ok(u) => u,
		Err(e) => return Err(Error::Other(e.into())),
	};

	let trading_pair = TradingPair { crypto_currency, fiat_currency };
	let mut coingecko_client = ExchangeRateClient::new(url.clone(), Arc::new(OcallApi));
	let rate = match coingecko_client.get_exchange_rate(trading_pair.clone()) {
		Ok(r) => r,
		Err(e) => {
			error!("[-] Failed to get the newest exchange rate from coingecko. {:?}", e);
			return Err(Error::Other(e.into()))
		},
	};

	let src = url.as_str();

	println!(
		"Update the exchange rate:  {} = {:?} for source {}",
		trading_pair.clone().key(),
		rate,
		src,
	);

	let call = OpaqueCall::from_tuple(&(
		[TEERACLE_MODULE, UPDATE_EXCHANGE_RATE],
		src.as_bytes().to_vec(),
		trading_pair.key().as_bytes().to_vec(),
		Some(rate),
	));

	let extrinsics = extrinsics_factory.create_extrinsics(vec![call].as_slice())?;
	Ok(extrinsics)
}
