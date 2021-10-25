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
	sidechain_impl::{exec_aura_on_slot, ProposerFactory},
	sync::{EnclaveLock, EnclaveStateRWLock, LightClientRwLock},
	utils::{
		hash_from_slice, now_as_u64, remaining_time, utf8_str_from_raw,
		write_slice_and_whitespace_pad, DecodeRaw, UnwrapOrSgxErrorUnexpected,
	},
};
use base58::ToBase58;
use codec::{alloc::string::String, Decode, Encode};
use ita_stf::{
	stf_sgx::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, Getter, ShardIdentifier, State as StfState, StatePayload, StateTypeDiff, Stf,
	TrustedCall, TrustedCallSigned, TrustedGetterSigned,
};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_responder::RpcResponder, rpc_ws_handler::RpcWsHandler,
};
use itc_light_client::{
	io::LightClientSeal, BlockNumberOps, HashFor, LightClientState, NumberFor, Validator,
};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::{
	node::{
		BLOCK_CONFIRMED, CALL_CONFIRMED, CALL_WORKER, REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION, SHIELD_FUNDS, TEEREX_MODULE,
	},
	sidechain::SLOT_DURATION,
};
use itp_sgx_crypto::{
	aes, ed25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal, ShieldingCrypto, StateCrypto,
};
use itp_sgx_io as io;
use itp_sgx_io::SealedIO;
use itp_stf_state_handler::{
	handle_state::HandleState, query_shard_state::QueryShardState, GlobalFileStateHandler,
};
use itp_storage::{StorageEntryVerified, StorageProof};
use itp_storage_verifier::GetStorageVerified;
use itp_types::{Block, CallWorkerFn, Header, OpaqueCall, ShieldFundsFn, SignedBlock};
use its_sidechain::{
	primitives::{
		traits::{Block as SidechainBlockT, SignBlock, SignedBlock as SignedBlockT},
		types::block::SignedBlock as SignedSidechainBlock,
	},
	slots::{duration_now, sgx::LastSlotSeal, yield_next_slot},
	state::{LastBlockExt, SidechainDB, SidechainState, SidechainSystemExt},
	top_pool::pool::Options as PoolOptions,
	top_pool_rpc_author::{
		api::SideChainApi,
		author::{Author, AuthorTopFilter},
		global_author_container::GlobalAuthorContainer,
		hash::TrustedOperationOrHash,
		pool_types::BPool,
		traits::{AuthorApi, GetAuthor, OnBlockCreated, SendState},
	},
};
use lazy_static::lazy_static;
use log::*;
use sgx_externalities::SgxExternalitiesTrait;
use sgx_types::sgx_status_t;
use sp_core::{blake2_256, crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::{
	generic::SignedBlock as SignedBlockG,
	traits::{Block as BlockT, Header as HeaderT, UniqueSaturatedInto},
	MultiSignature, OpaqueExtrinsic,
};
use std::{
	collections::HashMap,
	ops::Deref,
	slice,
	string::ToString,
	sync::{Arc, SgxRwLock},
	time::Duration,
	vec::Vec,
};
use substrate_api_client::{
	compose_extrinsic_offline, extrinsic::xt_primitives::UncheckedExtrinsicV4,
};

mod attestation;
mod ipfs;
mod ocall;
mod utils;

pub mod cert;
pub mod error;
pub mod rpc;
mod sidechain_impl;
mod sync;
pub mod tls_ra;

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

lazy_static! {
	/// the enclave's parentchain nonce
	///
	/// This should be abstracted away better in the future. Currently, this only exists
	/// because we produce sidechain blocks faster that parentchain chain blocks. So for now this
	/// design suffices. Later, we also need to sync across parallel ecalls that might both result
	/// in parentchain xt's. Then we should probably think about how we want to abstract the global
	/// nonce.
	static ref NONCE: SgxRwLock<u32> = SgxRwLock::new(Default::default());
}

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

	*NONCE.write().expect("Encountered poisoned NONCE lock") = *nonce;

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

	let mut nonce = NONCE.write().expect("Encountered poisoned NONCE lock");

	let xt = compose_extrinsic_offline!(
		signer,
		call,
		*nonce,
		Era::Immortal,
		genesis_hash,
		genesis_hash,
		RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION
	)
	.encode();

	*nonce += 1;

	write_slice_and_whitespace_pad(extrinsic_slice, xt);
	sgx_status_t::SGX_SUCCESS
}

fn create_extrinsics<PB>(
	genesis_hash: HashFor<PB>,
	calls: Vec<OpaqueCall>,
	nonce: &mut u32,
) -> Result<Vec<OpaqueExtrinsic>>
where
	PB: BlockT<Hash = H256>,
{
	// get information for composing the extrinsic
	let signer = Ed25519Seal::unseal()?;
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let extrinsics_buffer: Vec<OpaqueExtrinsic> = calls
		.into_iter()
		.map(|call| {
			let xt = compose_extrinsic_offline!(
				signer.clone(),
				call,
				*nonce,
				Era::Immortal,
				genesis_hash,
				genesis_hash,
				RUNTIME_SPEC_VERSION,
				RUNTIME_TRANSACTION_VERSION
			)
			.encode();
			*nonce += 1;
			xt
		})
		.map(|xt| {
			OpaqueExtrinsic::from_bytes(&xt)
				.expect("A previously encoded extrinsic has valid codec; qed.")
		})
		.collect();

	Ok(extrinsics_buffer)
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

	let io = side_chain_io_handler(move |signed_blocks| {
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
	let rpc_responder = Arc::new(RpcResponder::new(connection_registry.clone()));

	let side_chain_api = Arc::new(SideChainApi::<itp_types::Block>::new());
	let top_pool = Arc::new(BPool::create(PoolOptions::default(), side_chain_api, rpc_responder));
	let state_facade = Arc::new(GlobalFileStateHandler);

	let rsa_shielding_key = match Rsa3072Seal::unseal() {
		Ok(k) => k,
		Err(e) => {
			error!("Failed to unseal shielding key: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let rpc_author =
		Arc::new(Author::new(top_pool, AuthorTopFilter {}, state_facade, rsa_shielding_key));

	GlobalAuthorContainer::initialize(rpc_author.clone());

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
pub unsafe extern "C" fn execute_trusted_getters() -> sgx_status_t {
	if let Err(e) = execute_trusted_getters_on_all_shards() {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`execute_trusted_getters`] function to be able to use the `?` operator.
///
/// Executes trusted getters for a scheduled amount of time (defined by settings).
fn execute_trusted_getters_on_all_shards() -> Result<()> {
	use itp_settings::enclave::MAX_TRUSTED_GETTERS_EXEC_DURATION;

	let author_mutex = GlobalAuthorContainer.get().ok_or_else(|| {
		error!("Failed to retrieve author mutex. It might not be initialized?");
		Error::MutexAccess
	})?;

	let rpc_author = author_mutex.lock().unwrap().deref().clone();

	let state_handler = GlobalFileStateHandler;

	let shards = state_handler.list_shards()?;
	let mut remaining_shards = shards.len() as u32;
	let ends_at = duration_now() + MAX_TRUSTED_GETTERS_EXEC_DURATION;

	// Execute trusted getters for each shard. Each shard gets equal amount of time to execute
	// getters.
	for shard in shards.into_iter() {
		let shard_exec_time = match remaining_time(ends_at)
			.map(|r| r.checked_div(remaining_shards))
			.flatten()
		{
			Some(t) => t,
			None => {
				info!("[Enclave] Could not execute trusted operations for all shards. Remaining number of shards: {}.", remaining_shards);
				break
			},
		};

		match execute_trusted_getters_on_shard(
			rpc_author.as_ref(),
			&state_handler,
			shard,
			shard_exec_time,
		) {
			Ok(()) => {},
			Err(e) => error!("Error in trusted getter execution for shard {:?}: {:?}", shard, e),
		}

		remaining_shards -= 1;
	}

	Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn execute_trusted_calls() -> sgx_status_t {
	if let Err(e) = execute_trusted_calls_internal::<Block>() {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`execute_trusted_calls`] function to be able to use the `?` operator.
///
/// Executes `Aura::on_slot() for `slot` if it is this enclave's `Slot`.
///
/// This function makes an ocall that does the following:
///
/// *   sends sidechain `confirm_block` xt's with the produced sidechain blocks
/// *   gossip produced sidechain blocks to peer validateers.
fn execute_trusted_calls_internal<PB>() -> Result<()>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
{
	// we acquire lock explicitly (variable binding), since '_' will drop the lock after the statement
	// see https://medium.com/codechain/rust-underscore-does-not-bind-fec6a18115a8
	let (_light_client_lock, _side_chain_lock) = EnclaveLock::write_all()?;

	let mut validator = LightClientSeal::<PB>::unseal()?;
	let mut nonce = NONCE.write().expect("Encountered poisoned NONCE lock");

	let authority = Ed25519Seal::unseal()?;

	let author_mutex = GlobalAuthorContainer.get().ok_or_else(|| {
		error!("Failed to retrieve author mutex. It might not be initialized?");
		Error::MutexAccess
	})?;

	let rpc_author = author_mutex.lock().unwrap().deref().clone();
	let state_handler = Arc::new(GlobalFileStateHandler);

	let latest_onchain_header = validator.latest_finalized_header(validator.num_relays()).unwrap();

	match yield_next_slot(duration_now(), SLOT_DURATION, latest_onchain_header, &mut LastSlotSeal)?
	{
		Some(slot) => {
			let shards = state_handler.list_shards()?;
			let env = ProposerFactory::new(Arc::new(OcallApi), rpc_author, state_handler);

			exec_aura_on_slot::<_, _, SignedSidechainBlock, _, _, _>(
				slot,
				authority,
				&mut validator,
				OcallApi,
				env,
				&mut nonce,
				shards,
			)?
		},
		None => {
			debug!("No slot yielded. Skipping block production.");
			return Ok(())
		},
	};

	LightClientSeal::seal(validator)?;

	Ok(())
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
	let mut nonce = NONCE.write().expect("Encountered poisoned NONCE lock");

	sync_blocks_on_light_client(
		blocks_to_sync,
		&mut validator,
		&OcallApi,
		&GlobalFileStateHandler,
		&mut *nonce,
	)?;

	// store updated state in light client in case we fail afterwards.
	LightClientSeal::seal(validator)?;

	Ok(())
}

fn sync_blocks_on_light_client<PB, V, OCallApi, StateHandler>(
	blocks_to_sync: Vec<SignedBlockG<PB>>,
	validator: &mut V,
	on_chain_ocall_api: &OCallApi,
	state_handler: &StateHandler,
	nonce: &mut u32,
) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	V: Validator<PB> + LightClientState<PB>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StateHandler: HandleState,
{
	let mut calls = Vec::<OpaqueCall>::new();

	debug!("Syncing light client!");
	for signed_block in blocks_to_sync.into_iter() {
		validator
			.check_xt_inclusion(validator.num_relays(), &signed_block.block)
			.unwrap(); // panic can only happen if relay_id does not exist

		if let Err(e) = validator.submit_simple_header(
			validator.num_relays(),
			signed_block.block.header().clone(),
			signed_block.justifications.clone(),
		) {
			error!("Block verification failed. Error : {:?}", e);
			return Err(e.into())
		}

		if let Err(e) = update_states::<PB, _, _>(
			signed_block.block.header().clone(),
			on_chain_ocall_api,
			state_handler,
		) {
			error!("Error performing state updates upon block import");
			return Err(e)
		}

		// execute indirect calls, incl. shielding and unshielding
		match scan_block_for_relevant_xt(&signed_block.block, on_chain_ocall_api, state_handler) {
			// push shield funds to opaque calls
			Ok(c) => calls.extend(c.into_iter()),
			Err(_) => error!("Error executing relevant extrinsics"),
		};

		// compose indirect block confirmation
		let xt_block = [TEEREX_MODULE, BLOCK_CONFIRMED];
		let genesis_hash = validator.genesis_hash(validator.num_relays()).unwrap();
		let block_hash = signed_block.block.header().hash();
		let prev_state_hash = signed_block.block.header().parent_hash();
		calls.push(OpaqueCall::from_tuple(&(
			xt_block,
			genesis_hash,
			block_hash,
			prev_state_hash.encode(),
		)));
	}

	prepare_and_send_xts_and_block::<_, SignedSidechainBlock, _, _>(
		validator,
		on_chain_ocall_api,
		calls,
		Default::default(),
		nonce,
	)
}

fn prepare_and_send_xts_and_block<Block, SB, V, OCallApi>(
	validator: &mut V,
	ocall_api: &OCallApi,
	calls: Vec<OpaqueCall>,
	blocks: Vec<SB>,
	nonce: &mut u32,
) -> Result<()>
where
	Block: BlockT<Hash = H256>,
	SB: SignedBlockT + 'static,
	NumberFor<Block>: BlockNumberOps,
	V: Validator<Block> + LightClientState<Block>,
	OCallApi: EnclaveOnChainOCallApi,
{
	// store extrinsics in light client for finalization check
	let extrinsics = create_extrinsics::<Block>(
		validator.genesis_hash(validator.num_relays()).unwrap(),
		calls,
		nonce,
	)?;

	for xt in extrinsics.iter() {
		validator.submit_xt_to_be_included(validator.num_relays(), xt.clone()).unwrap();
	}

	ocall_api
		.send_block_and_confirmation::<SB>(extrinsics, blocks)
		.map_err(|e| Error::Other(format!("Failed to send block and confirmation: {}", e).into()))
}

/// Execute pending trusted operations for all shards until the [`max_exec_duration`] is reached.
///
/// For fairness, the [`max_exec_duration`] is split equally among all shards. Leftover time from
/// the previous shard is evenly distributed to all remaining shards.
///
/// Todo: This will probably be used again if we decide to make sidechain optional?
#[allow(unused)]
fn exec_trusted_calls_for_all_shards<PB, SB, OCallApi, RpcAuthor, StateHandler>(
	ocall_api: &OCallApi,
	rpc_author: &RpcAuthor,
	state_handler: &StateHandler,
	latest_onchain_header: &PB::Header,
	max_exec_duration: Duration,
) -> Result<(Vec<OpaqueCall>, Vec<SB>)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	RpcAuthor:
		AuthorApi<H256, PB::Hash> + SendState<Hash = PB::Hash> + OnBlockCreated<Hash = PB::Hash>,
	StateHandler: HandleState + QueryShardState,
{
	let shards = state_handler.list_shards()?;
	let mut calls: Vec<OpaqueCall> = Vec::new();
	let mut signed_blocks: Vec<SB> = Vec::with_capacity(shards.len());
	let mut remaining_shards = shards.len() as u32;
	let ends_at = duration_now() + max_exec_duration;

	// execute pending calls from operation pool and create block
	for shard in shards.into_iter() {
		let shard_exec_time = match remaining_time(ends_at)
			.map(|r| r.checked_div(remaining_shards))
			.flatten()
		{
			Some(t) => t,
			None => {
				info!("[Enclave] Could not execute trusted operations for all shards. Remaining shards: {}.", remaining_shards);
				break
			},
		};

		match exec_trusted_calls::<PB, SB, _, _, _>(
			ocall_api,
			rpc_author,
			state_handler,
			&latest_onchain_header,
			shard,
			shard_exec_time,
		) {
			Ok((confirm_calls, sb)) => {
				calls.extend(confirm_calls);
				if let Some(sb) = sb {
					signed_blocks.push(sb);
				}
			},
			Err(e) => error!("Error in top execution for shard {:?}: {:?}", shard, e),
		}

		remaining_shards -= 1;
	}
	Ok((calls, signed_blocks))
}

/// Execute pending trusted calls for the `shard` until `max_exec_duration` is reached.
///
/// This function returns:
/// *   The parentchain calls produced by the `Stf` to be wrapped in an extrinsic and sent to the parentchain
///     including the `confirm_block` call for the produced sidechain block.
/// *   The produced sidechain block.
///
/// Todo: This function does too much, but it needs anyhow some refactoring here to make the code
/// more readable.
fn exec_trusted_calls<PB, SB, OCallApi, RpcAuthor, StateHandler>(
	on_chain_ocall: &OCallApi,
	rpc_author: &RpcAuthor,
	state_handler: &StateHandler,
	latest_onchain_header: &PB::Header,
	shard: H256,
	max_exec_duration: Duration,
) -> Result<(Vec<OpaqueCall>, Option<SB>)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	OCallApi: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	RpcAuthor: AuthorApi<H256, PB::Hash> + OnBlockCreated<Hash = PB::Hash>,
	StateHandler: HandleState,
{
	let ends_at = duration_now() + max_exec_duration;

	// retrieve trusted operations from pool
	let trusted_calls = rpc_author.get_pending_tops_separated(shard)?.0;

	// Todo: remove when we have proper on-boarding of new workers #273.
	if trusted_calls.is_empty() {
		info!("No trusted calls in top for shard: {:?}", shard);
	// we return here when we actually import sidechain blocks because we currently have no
	// means of worker on-boarding. Without on-boarding we have can't get a working multi
	// worker-setup.
	//
	// But if we use this trick (only produce a sidechain block if there are trusted_calls), we
	// we can simply wait with the submission of trusted calls until all workers are ready. Then
	// we don't need to exchange any state and can have a functional multi-worker setup.
	// return Ok(Default::default())
	} else {
		debug!("Got following trusted calls from pool: {:?}", trusted_calls);
	}

	let mut calls = Vec::<OpaqueCall>::new();
	let mut call_hashes = Vec::<H256>::new();

	// load state before executing any calls
	let (mut sidechain_db, state_lock) = state_handler
		.load_for_mutation(&shard)
		.map(|(l, s)| (SidechainDB::<SB::Block, _>::new(s), l))?;

	let prev_state_hash = sidechain_db.state_hash();
	trace!("state apriori hash: {:?}", prev_state_hash);

	// update state needed for pallets
	sidechain_db.set_block_number(&sidechain_db.get_block_number().map_or(1, |n| n + 1));
	sidechain_db.set_timestamp(&now_as_u64());

	// retrieve trusted operations from pool
	let trusted_calls = rpc_author.get_pending_tops_separated(shard)?.0;

	debug!("Got following trusted calls from pool: {:?}", trusted_calls);
	// call execution
	for trusted_call_signed in trusted_calls.into_iter() {
		match handle_trusted_worker_call::<PB, _>(
			&mut calls,
			&mut sidechain_db.ext,
			&trusted_call_signed,
			latest_onchain_header,
			shard,
			on_chain_ocall,
		) {
			Ok(hashes) => {
				if let Some((_, op_hash)) = hashes {
					call_hashes.push(op_hash)
				}
				rpc_author
					.remove_top(
						vec![top_or_hash(trusted_call_signed, true)],
						shard,
						hashes.is_some(),
					)
					.unwrap();
			},
			Err(e) =>
				error!("Error performing worker call (will not push top hash): Error: {:?}", e),
		};
		// Check time
		if ends_at < duration_now() {
			break
		}
	}

	// Todo: this function should return here. Composing the block should be done by the caller.
	// create new block (side-chain)
	let block = match compose_block_and_confirmation::<PB, SB, _>(
		latest_onchain_header,
		call_hashes,
		shard,
		prev_state_hash,
		&mut sidechain_db,
	) {
		Ok((block_confirm, signed_block)) => {
			calls.push(block_confirm);

			// Notify watching clients of InSidechainBlock
			let block = signed_block.block();
			rpc_author.on_block_created(block.signed_top_hashes(), block.hash());

			Some(signed_block)
		},
		Err(e) => {
			error!("Could not compose block confirmation: {:?}", e);
			None
		},
	};

	// save updated state after call executions
	let _hash = state_handler.write(sidechain_db.ext, state_lock, &shard)?;

	if block.is_none() {
		info!("[Enclave] did not produce a block for shard {:?}", shard);
	}

	Ok((calls, block))
}

/// Execute pending trusted getters for the `shard` until `max_exec_duration` is reached.
fn execute_trusted_getters_on_shard<RpcAuthor, StateHandler>(
	rpc_author: &RpcAuthor,
	state_handler: &StateHandler,
	shard: H256,
	max_exec_duration: Duration,
) -> Result<()>
where
	RpcAuthor: AuthorApi<H256, H256> + SendState<Hash = H256>,
	StateHandler: HandleState,
{
	let ends_at = duration_now() + max_exec_duration;

	// retrieve trusted operations from pool
	let trusted_getters = rpc_author.get_pending_tops_separated(shard)?.1;

	// return early if we have no trusted getters, so we don't decrypt the state unnecessarily
	if trusted_getters.is_empty() {
		return Ok(())
	}

	// load state once per shard
	let mut state = state_handler
		.load_initialized(&shard)
		.map_err(|e| Error::Stf(format!("Error loading shard {:?}: Error: {:?}", shard, e)))?;
	trace!("Successfully loaded stf state");

	for trusted_getter_signed in trusted_getters.into_iter() {
		let hash_of_getter = rpc_author.hash_of(&trusted_getter_signed.clone().into());

		// get state
		match get_stf_state(trusted_getter_signed, &mut state) {
			Ok(r) => {
				// let client know of current state
				trace!("Updating client");
				match rpc_author.send_state(hash_of_getter, r.encode()) {
					Ok(_) => trace!("Successfully updated client"),
					Err(e) => error!("Could not send state to client {:?}", e),
				}
			},
			Err(e) => {
				error!("failed to get stf state, skipping trusted getter ({:?})", e);
			},
		};

		// remove getter from pool
		if let Err(e) =
			rpc_author.remove_top(vec![TrustedOperationOrHash::Hash(hash_of_getter)], shard, false)
		{
			error!("Error removing trusted operation from top pool: Error: {:?}", e);
		}

		// Check time
		if ends_at < duration_now() {
			return Ok(())
		}
	}

	Ok(())
}

/// Execute a trusted getter on a state and return its value, if available.
///
/// Also verifies the signature of the trusted getter and returns an error
/// if it's invalid.
fn get_stf_state(
	trusted_getter_signed: TrustedGetterSigned,
	state: &mut StfState,
) -> Result<Option<Vec<u8>>> {
	debug!("verifying signature of TrustedGetterSigned");
	if let false = trusted_getter_signed.verify_signature() {
		return Err(Error::Stf("bad signature".to_string()))
	}

	debug!("calling into STF to get state");
	Ok(Stf::get_state(state, trusted_getter_signed.into()))
}

/// Composes a sidechain block of a shard
pub fn compose_block_and_confirmation<PB, SB, SidechainDB>(
	latest_onchain_header: &PB::Header,
	top_call_hashes: Vec<H256>,
	shard: ShardIdentifier,
	state_hash_apriori: H256,
	db: &mut SidechainDB,
) -> Result<(OpaqueCall, SB)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	SidechainDB: LastBlockExt<SB::Block> + SidechainState<Hash = H256>,
{
	let signer_pair = Ed25519Seal::unseal()?;
	let state_hash_new = db.state_hash();

	let (block_number, parent_hash) = match db.get_last_block() {
		Some(block) => (block.block_number() + 1, block.hash()),
		None => {
			info!("Seems to be first sidechain block.");
			(1, Default::default())
		},
	};

	if block_number != db.get_block_number().unwrap_or(0) {
		return Err(Error::Other("[Sidechain] BlockNumber is not LastBlock's Number + 1".into()))
	}

	// create encrypted payload
	let mut payload: Vec<u8> =
		StatePayload::new(state_hash_apriori, state_hash_new, db.ext().state_diff().clone())
			.encode();
	AesSeal::unseal().map(|key| key.encrypt(&mut payload))??;

	let block = SB::Block::new(
		signer_pair.public(),
		block_number,
		parent_hash,
		latest_onchain_header.hash(),
		shard,
		top_call_hashes,
		payload,
		now_as_u64(),
	);

	let block_hash = block.hash();
	debug!("Block hash {}", block_hash);
	db.set_last_block(&block);

	// state diff has been written to block, clean it for the next block.
	db.ext_mut().prune_state_diff();

	let xt_block = [TEEREX_MODULE, BLOCK_CONFIRMED];
	let opaque_call =
		OpaqueCall::from_tuple(&(xt_block, shard, block_hash, state_hash_new.encode()));
	Ok((opaque_call, block.sign_block(&signer_pair)))
}

pub fn update_states<PB, O, StateHandler>(
	header: PB::Header,
	on_chain_ocall_api: &O,
	state_handler: &StateHandler,
) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	O: EnclaveOnChainOCallApi,
	StateHandler: HandleState,
{
	debug!("Update STF storage upon block import!");
	let storage_hashes = Stf::storage_hashes_to_update_on_block();

	if storage_hashes.is_empty() {
		return Ok(())
	}

	// global requests they are the same for every shard
	let state_diff_update: StateTypeDiff = on_chain_ocall_api
		.get_multiple_storages_verified(storage_hashes, &header)
		.map(into_map)?
		.into();

	// look for new shards an initialize them
	if let Some(maybe_shards) = state_diff_update.get(&shards_key_hash()) {
		match maybe_shards {
			Some(shards) => {
				let shards: Vec<ShardIdentifier> = Decode::decode(&mut shards.as_slice())
					.sgx_error_with_log("error decoding shards")?;

				for shard_id in shards {
					let (state_lock, mut state) = state_handler.load_for_mutation(&shard_id)?;
					trace!("Successfully loaded state, updating states ...");

					// per shard (cid) requests
					let per_shard_hashes = storage_hashes_to_update_per_shard(&shard_id);
					let per_shard_update = on_chain_ocall_api
						.get_multiple_storages_verified(per_shard_hashes, &header)
						.map(into_map)?;

					Stf::update_storage(&mut state, &per_shard_update.into());
					Stf::update_storage(&mut state, &state_diff_update);

					// block number is purged from the substrate state so it can't be read like other storage values
					// The number conversion is a bit unfortunate, but I wanted to prevent making the stf generic for now
					Stf::update_layer_one_block_number(
						&mut state,
						(*header.number()).unique_saturated_into(),
					);

					state_handler.write(state, state_lock, &shard_id)?;
				}
			},
			None => debug!("No shards are on the chain yet"),
		};
	};
	Ok(())
}

/// Scans blocks for extrinsics that ask the enclave to execute some actions.
/// Executes indirect invocation calls, as well as shielding and unshielding calls
/// Returns all unshielding call confirmations as opaque calls
pub fn scan_block_for_relevant_xt<PB, O, StateHandler>(
	block: &PB,
	on_chain_ocall: &O,
	state_handler: &StateHandler,
) -> Result<Vec<OpaqueCall>>
where
	PB: BlockT<Hash = H256>,
	O: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
	StateHandler: HandleState,
{
	debug!("Scanning block {:?} for relevant xt", block.header().number());
	let mut opaque_calls = Vec::<OpaqueCall>::new();
	for xt_opaque in block.extrinsics().iter() {
		// shield funds XT
		if let Ok(xt) =
			UncheckedExtrinsicV4::<ShieldFundsFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			// confirm call decodes successfully as well
			if xt.function.0 == [TEEREX_MODULE, SHIELD_FUNDS] {
				if let Err(e) = handle_shield_funds_xt(&mut opaque_calls, xt, state_handler) {
					error!("Error performing shield funds. Error: {:?}", e);
				}
			}
		};

		// call worker XT
		if let Ok(xt) =
			UncheckedExtrinsicV4::<CallWorkerFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			if xt.function.0 == [TEEREX_MODULE, CALL_WORKER] {
				if let Ok((decrypted_trusted_call, shard)) = decrypt_unchecked_extrinsic(xt) {
					// load state before executing any calls
					let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;
					// call execution
					trace!("Handling trusted worker call of state: {:?}", state);
					if let Err(e) = handle_trusted_worker_call::<PB, _>(
						&mut opaque_calls, // necessary for unshielding
						&mut state,
						&decrypted_trusted_call,
						block.header(),
						shard,
						on_chain_ocall,
					) {
						error!("Error performing worker call: Error: {:?}", e);
					}
					// save updated state

					// we only want to store the state diff for direct stuff.
					state.prune_state_diff();
					trace!("Updating state of shard {:?}", shard);
					state_handler.write(state, state_lock, &shard)?;
				}
			}
		}
	}

	Ok(opaque_calls)
}

fn handle_shield_funds_xt<StateHandler>(
	calls: &mut Vec<OpaqueCall>,
	xt: UncheckedExtrinsicV4<ShieldFundsFn>,
	state_handler: &StateHandler,
) -> Result<()>
where
	StateHandler: HandleState,
{
	let (call, account_encrypted, amount, shard) = xt.function.clone();
	info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        call, account_encrypted, amount, shard.encode().to_base58(),
    );

	let (state_lock, mut state) = state_handler.load_for_mutation(&shard)?;

	debug!("decrypt the call");
	//let account_vec = Rsa3072KeyPair::decrypt(&account_encrypted)?;
	let account_vec = Rsa3072Seal::unseal().map(|key| key.decrypt(&account_encrypted))??;

	let account = AccountId::decode(&mut account_vec.as_slice())
		.sgx_error_with_log("[ShieldFunds] Could not decode account")?;
	let root = Stf::get_root(&mut state);
	let nonce = Stf::account_nonce(&mut state, &root);

	if let Err(e) = Stf::execute(
		&mut state,
		TrustedCallSigned::new(
			TrustedCall::balance_shield(root, account, amount),
			nonce,
			Default::default(), //don't care about signature here
		),
		calls,
	) {
		error!("Error performing Stf::execute. Error: {:?}", e);
		return Ok(())
	}

	let state_hash = state_handler.write(state, state_lock, &shard)?;

	let xt_call = [TEEREX_MODULE, CALL_CONFIRMED];
	let xt_hash = blake2_256(&xt.encode());
	debug!("Extrinsic hash {:?}", xt_hash);

	calls.push(OpaqueCall::from_tuple(&(xt_call, shard, xt_hash, state_hash.encode())));

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

fn handle_trusted_worker_call<PB, O>(
	calls: &mut Vec<OpaqueCall>,
	state: &mut StfState,
	stf_call_signed: &TrustedCallSigned,
	header: &PB::Header,
	shard: ShardIdentifier,
	on_chain_ocall_api: &O,
) -> Result<Option<(H256, H256)>>
where
	PB: BlockT<Hash = H256>,
	O: EnclaveOnChainOCallApi + EnclaveAttestationOCallApi,
{
	debug!("query mrenclave of self");
	let mrenclave = on_chain_ocall_api.get_mrenclave_of_self()?;
	debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());

	if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
		error!("TrustedCallSigned: bad signature");
		// do not panic here or users will be able to shoot workers dead by supplying a bad signature
		return Ok(None)
	}

	// Necessary because light client sync may not be up to date
	// see issue #208
	debug!("Update STF storage!");
	let storage_hashes = Stf::get_storage_hashes_to_update(&stf_call_signed);
	let update_map = on_chain_ocall_api
		.get_multiple_storages_verified(storage_hashes, header)
		.map(into_map)?;
	Stf::update_storage(state, &update_map.into());

	debug!("execute STF");
	if let Err(e) = Stf::execute(state, stf_call_signed.clone(), calls) {
		error!("Error performing Stf::execute. Error: {:?}", e);
		return Ok(None)
	}

	let call_hash = blake2_256(&stf_call_signed.encode());
	let operation = stf_call_signed.clone().into_trusted_operation(true);
	let operation_hash = blake2_256(&operation.encode());
	debug!("Operation hash {:?}", operation_hash);
	debug!("Call hash {:?}", call_hash);

	Ok(Some((H256::from(call_hash), H256::from(operation_hash))))
}

pub fn into_map(
	storage_entries: Vec<StorageEntryVerified<Vec<u8>>>,
) -> HashMap<Vec<u8>, Option<Vec<u8>>> {
	storage_entries.into_iter().map(|e| e.into_tuple()).collect()
}

fn top_or_hash<H>(tcs: TrustedCallSigned, direct: bool) -> TrustedOperationOrHash<H> {
	TrustedOperationOrHash::<H>::Operation(tcs.into_trusted_operation(direct))
}
