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
	ocall::OcallApi,
	rpc::worker_api_direct::{public_api_rpc_handler, side_chain_io_handler},
	sync::{EnclaveLock, LightClientRwLock},
	utils::{
		hash_from_slice, utf8_str_from_raw, write_slice_and_whitespace_pad, DecodeRaw,
		UnwrapOrSgxErrorUnexpected,
	},
};
use base58::ToBase58;
use beefy_merkle_tree::{merkle_root, Keccak256};
use codec::{alloc::string::String, Decode, Encode};
use ita_exchange_oracle::{coingecko::CoinGeckoClient, GetExchangeRate};
use ita_stf::{AccountId, Getter, ShardIdentifier, Stf, TrustedCallSigned};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_ws_handler::RpcWsHandler,
};
use itc_light_client::{
	io::LightClientSeal, BlockNumberOps, LightClientState, NumberFor, Validator,
};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_extrinsics_factory::{CreateExtrinsics, ExtrinsicsFactory};
use itp_nonce_cache::{MutateNonce, Nonce, GLOBAL_NONCE_CACHE};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::node::{
	CALL_WORKER, PROCESSED_PARENTCHAIN_BLOCK, REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION,
	RUNTIME_TRANSACTION_VERSION, SHIELD_FUNDS, TEERACLE_MODULE, TEEREX_MODULE,
	UPDATE_EXCHANGE_RATE,
};
use itp_sgx_crypto::{aes, ed25519, rsa3072, Ed25519Seal, Rsa3072Seal, ShieldingCrypto};
use itp_sgx_io as io;
use itp_sgx_io::SealedIO;
use itp_stf_executor::{
	executor::StfExecutor,
	traits::{StatePostProcessing, StfExecuteShieldFunds, StfExecuteTrustedCall, StfUpdateState},
};
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState, GlobalFileStateHandler,
};
use itp_storage::StorageProof;
use itp_types::{Block, CallWorkerFn, Header, OpaqueCall, ShieldFundsFn, SignedBlock};
use its_sidechain::top_pool_rpc_author::{
	global_author_container::GlobalAuthorContainer, traits::GetAuthor,
};
use log::*;
use sgx_types::sgx_status_t;
use sp_core::{blake2_256, crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::{
	generic::SignedBlock as SignedBlockG,
	traits::{Block as BlockT, Header as HeaderT},
	OpaqueExtrinsic,
};
use std::{slice, sync::Arc, vec::Vec};
use substrate_api_client::{
	compose_extrinsic_offline, extrinsic::xt_primitives::UncheckedExtrinsicV4,
};
use substrate_fixed::types::U32F32;

mod attestation;
mod ipfs;
mod ocall;
mod utils;

pub mod cert;
pub mod error;
pub mod rpc;
mod sidechain_block_composer;
mod sidechain_impl;
mod sync;
pub mod tls_ra;
pub mod top_pool_execution;
mod top_pool_operation_executor;

mod beefy_merkle_tree;

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
pub unsafe extern "C" fn init() -> sgx_status_t {
	// initialize the logging environment in the enclave
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

	// create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attastation is performed with the primary worker
	if let Err(e) = aes::create_sealed_if_absent().map_err(Error::Crypto) {
		return e.into()
	}

	let state_handler = GlobalFileStateHandler;

	// for debug purposes, list shards. no problem to panic if fails
	let shards = state_handler.list_shards().unwrap();
	debug!("found the following {} shards on disk:", shards.len());
	for s in shards {
		debug!("{}", s.encode().to_base58())
	}
	//shards.into_iter().map(|s| debug!("{}", s.encode().to_base58()));

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

	let res = match side_chain_rpc_int::<Block, _>(request, OcallApi) {
		Ok(res) => res,
		Err(e) => return e.into(),
	};

	let response_slice = slice::from_raw_parts_mut(response, response_len as usize);
	write_slice_and_whitespace_pad(response_slice, res.into_bytes());

	sgx_status_t::SGX_SUCCESS
}

fn side_chain_rpc_int<PB, O>(request: &str, _ocall_api: O) -> Result<String>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	O: EnclaveOnChainOCallApi + 'static,
{
	// Skip sidechain import now until #423 is solved.
	// let _ = EnclaveLock::read_all()?;
	//
	// let header = LightClientSeal::<PB>::unseal()
	// 	.map(|v| v.latest_finalized_header(v.num_relays()).unwrap())?;
	//
	// let importer: BlockImporter<AuthorityPair, PB, _, O, _> = BlockImporter::default();
	//
	// let io = side_chain_io_handler(move |signed_blocks| {
	// 	import_sidechain_blocks::<PB, _, _, _>(signed_blocks, &header, importer.clone(), &ocall_api)
	// });

	let io = side_chain_io_handler::<_, crate::error::Error>(move |signed_blocks| {
		log::info!("[sidechain] Imported blocks: {:?}", signed_blocks);
		Ok(())
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

/// Call this once at worker startup to initialize the TOP pool and direct invocation RPC server
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

	its_sidechain::top_pool_rpc_author::initializer::initialize_top_pool_rpc_author(
		connection_registry.clone(),
		rsa_shielding_key,
	);

	let rpc_author = match GlobalAuthorContainer.get() {
		Some(a) => a,
		None => {
			error!("Failed to retrieve global top pool author");
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

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

	match itc_light_client::io::read_or_init_validator::<Block>(header, auth, proof) {
		Ok(header) => write_slice_and_whitespace_pad(latest_header_slice, header.encode()),
		Err(e) => return e.into(),
	}
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn sync_parentchain(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	nonce: *const u32,
) -> sgx_status_t {
	let blocks_to_sync = match Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size) {
		Ok(blocks) => blocks,
		Err(e) => return Error::Codec(e).into(),
	};

	if let Err(e) = sync_parentchain_internal::<Block>(blocks_to_sync, *nonce) {
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
fn sync_parentchain_internal<PB>(blocks_to_sync: Vec<SignedBlockG<PB>>, _nonce: u32) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
{
	// we acquire lock explicitly (variable binding), since '_' will drop the lock after the statement
	// see https://medium.com/codechain/rust-underscore-does-not-bind-fec6a18115a8
	let _light_client_lock = EnclaveLock::write_light_client_db()?;

	let mut validator = LightClientSeal::<PB>::unseal()?;
	let signer = Ed25519Seal::unseal()?;
	let stf_executor = StfExecutor::new(Arc::new(OcallApi), Arc::new(GlobalFileStateHandler));
	let genesis_hash = validator.genesis_hash(validator.num_relays())?;
	let extrinsics_factory =
		ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone());

	sync_blocks_on_light_client(
		blocks_to_sync,
		&mut validator,
		&extrinsics_factory,
		&OcallApi,
		&stf_executor,
	)?;

	// store updated state in light client in case we fail afterwards.
	LightClientSeal::seal(validator)?;

	Ok(())
}

fn sync_blocks_on_light_client<PB, V, OCallApi, StfExecutor, ExtrinsicsFactory>(
	blocks_to_sync: Vec<SignedBlockG<PB>>,
	validator: &mut V,
	extrinsics_factory: &ExtrinsicsFactory,
	on_chain_ocall_api: &OCallApi,
	stf_executor: &StfExecutor,
) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	V: Validator<PB> + LightClientState<PB>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StfExecutor: StfUpdateState + StfExecuteTrustedCall + StfExecuteShieldFunds,
	ExtrinsicsFactory: CreateExtrinsics,
{
	let mut calls = Vec::<OpaqueCall>::new();

	debug!("Syncing light client!");
	for signed_block in blocks_to_sync.into_iter() {
		let block = signed_block.block;
		validator.check_xt_inclusion(validator.num_relays(), &block).unwrap(); // panic can only happen if relay_id does not exist

		if let Err(e) = validator.submit_simple_header(
			validator.num_relays(),
			block.header().clone(),
			signed_block.justifications.clone(),
		) {
			error!("Block verification failed. Error : {:?}", e);
			return Err(e.into())
		}

		if let Err(e) = stf_executor.update_states::<PB>(&block.header()) {
			error!("Error performing state updates upon block import");
			return Err(e.into())
		}

		// execute indirect calls, incl. shielding and unshielding
		match scan_block_for_relevant_xt(&block, stf_executor) {
			Ok((unshielding_call_confirmations, executed_shielding_calls)) => {
				// Include all unshieldung confirmations that need to be executed on the parentchain.
				calls.extend(unshielding_call_confirmations.into_iter());
				// Include a processed parentchain block confirmation for each block.
				calls.push(create_processed_parentchain_block_call(
					block.hash(),
					executed_shielding_calls,
				));
			},
			Err(_) => error!("Error executing relevant extrinsics"),
		};
	}

	let xts = extrinsics_factory.create_extrinsics(calls.as_slice())?;

	validator.send_extrinsics(on_chain_ocall_api, xts)?;

	Ok(())
}

/// For now get the DOT/currency exchange rate from coingecko API.
#[no_mangle]
pub unsafe extern "C" fn update_market_data_xt(
	currency: *const u8,
	currency_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let mut curr_slice = slice::from_raw_parts(currency, currency_size as usize);
	let curr: String = Decode::decode(&mut curr_slice).unwrap();
	let xts = match update_market_data_internal::<Block>(curr) {
		Ok(xts) => xts,
		Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	// Only one extrinsic to send over the node api directly.
	let xt = match xts.get(0) {
		Some(xt) => xt,
		None => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	// Save created extrinsic as slice in the return value unchecked_extrinsic.
	write_slice_and_whitespace_pad(extrinsic_slice, xt.encode());
	sgx_status_t::SGX_SUCCESS
}

fn update_market_data_internal<PB>(curr: String) -> Result<Vec<OpaqueExtrinsic>>
where
	PB: BlockT<Hash = H256>,
{
	let signer = Ed25519Seal::unseal()?;
	let light_client_lock = EnclaveLock::read_light_client_db()?;
	let validator = LightClientSeal::<PB>::unseal()?;
	let genesis_hash = validator.genesis_hash(validator.num_relays())?;
	LightClientSeal::seal(validator)?;
	std::mem::drop(light_client_lock);

	let extrinsics_factory =
		ExtrinsicsFactory::new(genesis_hash, signer, GLOBAL_NONCE_CACHE.clone());

	// For now hardcoded polkadot
	let coin = "polkadot";

	// Get the exchange rate
	let url = match CoinGeckoClient::base_url() {
		Ok(u) => u,
		Err(e) => return Err(Error::Other(e.into())),
	};

	let mut coingecko_client = CoinGeckoClient::new(url);
	let rate = match coingecko_client.get_exchange_rate(coin, &curr) {
		Ok(r) => r,
		Err(e) => {
			error!("[-] Failed to get the newest exchange rate from coingecko. {:?}", e);
			return Err(Error::Other(e.into()))
		},
	};

	println!(
		"Update the exchange rate: 1 DOT = {:?} {}",
		Some(U32F32::from_num(rate)).unwrap(),
		curr.to_uppercase()
	);
	let call = OpaqueCall::from_tuple(&(
		[TEERACLE_MODULE, UPDATE_EXCHANGE_RATE],
		curr.encode(),
		Some(U32F32::from_num(rate)),
	));
	let extrinsics = extrinsics_factory.create_extrinsics(vec![call].as_slice())?;
	Ok(extrinsics)
}

/// Creates a processed_parentchain_block extrinsic for a given parentchain block hash and the merkle executed extrinsics.
///
/// Calculates the merkle root of the extrinsics. In case no extrinsics are supplied, the root will be a hash filled with zeros.
fn create_processed_parentchain_block_call(block_hash: H256, extrinsics: Vec<H256>) -> OpaqueCall {
	let root: H256 = merkle_root::<Keccak256, _, _>(extrinsics).into();
	OpaqueCall::from_tuple(&([TEEREX_MODULE, PROCESSED_PARENTCHAIN_BLOCK], block_hash, root))
}

/// Scans blocks for extrinsics that ask the enclave to execute some actions.
/// Executes indirect invocation calls, including shielding and unshielding calls.
/// Returns all unshielding call confirmations as opaque calls and the hashes of executed shielding calls.
fn scan_block_for_relevant_xt<PB, StfExecutor>(
	block: &PB,
	stf_executor: &StfExecutor,
) -> Result<(Vec<OpaqueCall>, Vec<H256>)>
where
	PB: BlockT<Hash = H256>,
	StfExecutor: StfUpdateState + StfExecuteTrustedCall + StfExecuteShieldFunds,
{
	debug!("Scanning block {:?} for relevant xt", block.header().number());
	let mut opaque_calls = Vec::<OpaqueCall>::new();
	let mut executed_shielding_calls = Vec::<H256>::new();
	for xt_opaque in block.extrinsics().iter() {
		// Found ShieldFunds extrinsic in block.
		if let Ok(xt) =
			UncheckedExtrinsicV4::<ShieldFundsFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			if xt.function.0 == [TEEREX_MODULE, SHIELD_FUNDS] {
				if let Err(e) = handle_shield_funds_xt(&xt, stf_executor) {
					error!("Error performing shield funds. Error: {:?}", e);
				} else {
					// Cache successfully executed shielding call.
					executed_shielding_calls.push(hash_of(xt))
				}
			}
		};

		// Found CallWorker extrinsic in block.
		if let Ok(xt) =
			UncheckedExtrinsicV4::<CallWorkerFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			if xt.function.0 == [TEEREX_MODULE, CALL_WORKER] {
				if let Ok((decrypted_trusted_call, shard)) = decrypt_unchecked_extrinsic(xt) {
					if let Err(e) = stf_executor.execute_trusted_call::<PB>(
						&mut opaque_calls,
						&decrypted_trusted_call,
						&block.header(),
						&shard,
						StatePostProcessing::Prune, // we only want to store the state diff for direct stuff.
					) {
						error!("Error executing trusted call: Error: {:?}", e);
					}
				}
			}
		}
	}
	Ok((opaque_calls, executed_shielding_calls))
}

fn hash_of<T: Encode>(xt: T) -> H256 {
	blake2_256(&xt.encode()).into()
}

fn handle_shield_funds_xt<StfExecutor>(
	xt: &UncheckedExtrinsicV4<ShieldFundsFn>,
	stf_executor: &StfExecutor,
) -> Result<()>
where
	StfExecutor: StfUpdateState + StfExecuteTrustedCall + StfExecuteShieldFunds,
{
	let (call, account_encrypted, amount, shard) = &xt.function;
	info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        call, account_encrypted, amount, shard.encode().to_base58(),
    );

	debug!("decrypt the call");
	let account_vec = Rsa3072Seal::unseal().map(|key| key.decrypt(&account_encrypted))??;

	let account = AccountId::decode(&mut account_vec.as_slice())
		.sgx_error_with_log("[ShieldFunds] Could not decode account")?;

	stf_executor.execute_shield_funds(account, *amount, shard)?;
	Ok(())
}

fn decrypt_unchecked_extrinsic(
	xt: UncheckedExtrinsicV4<CallWorkerFn>,
) -> Result<(TrustedCallSigned, ShardIdentifier)> {
	let (call, request) = xt.function;
	let (shard, cyphertext) = (request.shard, request.cyphertext);
	debug!("Found CallWorker extrinsic in block: \nCall: {:?} \nRequest: \nshard: {}\ncyphertext: {:?}",
        call,
        shard.encode().to_base58(),
        cyphertext
    );

	debug!("decrypt the call");
	//let request_vec = Rsa3072KeyPair::decrypt(&cyphertext)?;
	let request_vec = Rsa3072Seal::unseal().map(|key| key.decrypt(&cyphertext))??;

	Ok(TrustedCallSigned::decode(&mut request_vec.as_slice()).map(|call| (call, shard))?)
}
