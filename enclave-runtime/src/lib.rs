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
	rpc::worker_api_direct::public_api_rpc_handler,
	top_pool::{
		pool::Options as PoolOptions,
		pool_types::BPool,
		primitives::TrustedOperationPool,
		top_pool_container::{GetTopPool, GlobalTopPoolContainer},
	},
	utils::{
		hash_from_slice, remaining_time, write_slice_and_whitespace_pad, DecodeRaw,
		UnwrapOrSgxErrorUnexpected,
	},
};
use base58::ToBase58;
use codec::{alloc::string::String, Decode, Encode};
use core::ops::Deref;
use ita_stf::{
	stf_sgx_primitives::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, Getter, ShardIdentifier, State as StfState, State, StatePayload, StateTypeDiff, Stf,
	TrustedCall, TrustedCallSigned, TrustedGetterSigned,
};
use itc_direct_rpc_server::{
	create_determine_watch, rpc_connection_registry::ConnectionRegistry,
	rpc_responder::RpcResponder, rpc_ws_handler::RpcWsHandler,
};
use itc_light_client::{io::LightClientSeal, BlockNumberOps, NumberFor, Validator};
use itc_tls_websocket_server::{connection::TungsteniteWsConnection, run_ws_server};
use itp_ocall_api::{EnclaveAttestationOCallApi, EnclaveOnChainOCallApi};
use itp_settings::{
	enclave::MAX_TRUSTED_OPS_EXEC_DURATION,
	node::{
		BLOCK_CONFIRMED, CALL_CONFIRMED, CALL_WORKER, REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION, SHIELD_FUNDS, TEEREX_MODULE,
	},
};
use itp_sgx_crypto::{
	aes, ed25519, rsa3072, AesSeal, Ed25519Seal, Rsa3072Seal, ShieldingCrypto, StateCrypto,
};
use itp_sgx_io as io;
use itp_sgx_io::SealedIO;
use itp_storage::{StorageEntryVerified, StorageProof};
use itp_storage_verifier::GetStorageVerified;
use itp_types::{Block, CallWorkerFn, Header, OpaqueCall, ShieldFundsFn, SignedBlock};
use its_primitives::{
	traits::{Block as SidechainBlockT, SignBlock, SignedBlock as SignedBlockT},
	types::block::SignedBlock as SignedSidechainBlock,
};
use log::*;
use rpc::{
	api::SideChainApi,
	author::{hash::TrustedOperationOrHash, Author, AuthorApi},
};
use sgx_types::{sgx_status_t, SgxResult};
use sp_core::{blake2_256, crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::{
	generic::SignedBlock as SignedBlockG,
	traits::{Block as BlockT, Header as HeaderT, UniqueSaturatedInto},
	MultiSignature, OpaqueExtrinsic,
};
use std::{
	collections::HashMap,
	slice,
	string::ToString,
	sync::Arc,
	time::{Duration, SystemTime, UNIX_EPOCH},
	untrusted::time::SystemTimeEx,
	vec::Vec,
};
use substrate_api_client::{
	compose_extrinsic_offline, extrinsic::xt_primitives::UncheckedExtrinsicV4,
};
use utils::duration_now;

mod attestation;
mod ipfs;
mod ocall;
mod state;
mod utils;

pub mod cert;
pub mod error;
pub mod hex;
pub mod rpc;
pub mod tls_ra;
pub mod top_pool;

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

	// for debug purposes, list shards. no problem to panic if fails
	let shards = state::list_shards().unwrap();
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
pub unsafe extern "C" fn mock_register_enclave_xt(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u32,
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

	write_slice_and_whitespace_pad(extrinsic_slice, xt);
	sgx_status_t::SGX_SUCCESS
}

fn create_extrinsics<PB, V>(
	validator: &V,
	calls: Vec<OpaqueCall>,
	mut nonce: u32,
) -> Result<Vec<OpaqueExtrinsic>>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	V: Validator<PB>,
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
				nonce,
				Era::Immortal,
				validator.genesis_hash(validator.num_relays()).unwrap(),
				validator.genesis_hash(validator.num_relays()).unwrap(),
				RUNTIME_SPEC_VERSION,
				RUNTIME_TRANSACTION_VERSION
			)
			.encode();
			nonce += 1;
			xt
		})
		.map(|xt| {
			OpaqueExtrinsic::from_bytes(&xt)
				.expect("A previously encoded extrinsic has valid codec; qed.")
		})
		.collect();

	Ok(extrinsics_buffer)
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

	if !state::exists(&shard) {
		info!("Initialized new shard that was queried chain: {:?}", shard);
		if let Err(e) = state::init_shard(&shard) {
			return e.into()
		}
	}

	let mut state = match state::load(&shard) {
		Ok(s) => s,
		Err(e) => return e.into(),
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
	let top_pool = BPool::create(PoolOptions::default(), side_chain_api, rpc_responder);

	GlobalTopPoolContainer::initialize(top_pool);

	let io_handler = public_api_rpc_handler(Arc::new(GlobalTopPoolContainer));
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
pub unsafe extern "C" fn sync_parentchain_and_execute_tops(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	nonce: *const u32,
) -> sgx_status_t {
	let blocks_to_sync = match Vec::<SignedBlock>::decode_raw(blocks_to_sync, blocks_to_sync_size) {
		Ok(blocks) => blocks,
		Err(e) => return Error::Codec(e).into(),
	};

	if let Err(e) = sync_parentchain_and_execute_tops_int::<Block>(blocks_to_sync, *nonce) {
		return e.into()
	}

	sgx_status_t::SGX_SUCCESS
}

/// Internal [`sync_parentchain_and_execute_tops`] function to be able to use the handy `?` operator.
///
/// Sync parentchain blocks to the light-client and execute pending trusted operations.
///
/// This function makes an ocall that does the following:
///
/// *   send `confirm_call` xt's of the `Stf` functions executed due to in-/direct invocation to the
///     to the parentchain
/// *   sends sidechain `confirm_block` xt's with the produced sidechain blocks
/// *   gossip produced sidechain blocks to peer validateers.
fn sync_parentchain_and_execute_tops_int<PB>(
	blocks_to_sync: Vec<SignedBlockG<PB>>,
	nonce: u32,
) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
{
	let mut validator = LightClientSeal::<PB>::unseal()?;

	let mut calls = sync_blocks_on_light_client(blocks_to_sync, &mut validator, &OcallApi)?;

	let latest_onchain_header = validator.latest_finalized_header(validator.num_relays()).unwrap();

	// execute pending calls from operation pool and create block
	let signed_blocks = exec_tops_for_all_shards::<PB, SignedSidechainBlock, _, _>(
		&OcallApi,
		&GlobalTopPoolContainer,
		&latest_onchain_header,
		MAX_TRUSTED_OPS_EXEC_DURATION,
	)
	.map(|(confirm_calls, sb)| {
		calls.extend(confirm_calls);
		sb
	})?;

	let extrinsics = create_extrinsics(&validator, calls, nonce)?;

	// store extrinsics in light client for finalization check
	for xt in extrinsics.iter() {
		validator.submit_xt_to_be_included(validator.num_relays(), xt.clone()).unwrap();
	}

	LightClientSeal::seal(validator)?;

	// ocall to worker to store signed block and send block confirmation
	// send extrinsics to parentchain, gossip blocks to side-chain
	OcallApi
		.send_block_and_confirmation(extrinsics, signed_blocks)
		.map_err(|e| Error::Other(format!("Failed to send block and confirmation: {}", e).into()))
}

fn sync_blocks_on_light_client<PB, V, O>(
	blocks_to_sync: Vec<SignedBlockG<PB>>,
	validator: &mut V,
	on_chain_ocall_api: &O,
) -> Result<Vec<OpaqueCall>>
where
	PB: BlockT<Hash = H256>,
	NumberFor<PB>: BlockNumberOps,
	V: Validator<PB>,
	O: EnclaveOnChainOCallApi,
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

		if let Err(e) =
			update_states::<PB, _>(signed_block.block.header().clone(), on_chain_ocall_api)
		{
			error!("Error performing state updates upon block import");
			return Err(e)
		}

		// execute indirect calls, incl. shielding and unshielding
		match scan_block_for_relevant_xt(&signed_block.block, on_chain_ocall_api) {
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

	Ok(calls)
}

fn get_stf_state(
	trusted_getter_signed: TrustedGetterSigned,
	shard: ShardIdentifier,
) -> Result<Option<Vec<u8>>> {
	debug!("verifying signature of TrustedGetterSigned");
	if let false = trusted_getter_signed.verify_signature() {
		return Err(Error::Stf("bad signature".to_string()))
	}

	if !state::exists(&shard) {
		info!("Initialized new shard that was queried chain: {:?}", shard);
		if let Err(e) = state::init_shard(&shard) {
			return Err(Error::Stf(format!(
				"Error initialising shard {:?} state: Error: {:?}",
				shard, e
			)))
		}
	}

	let mut state = match state::load(&shard) {
		Ok(s) => s,
		Err(e) =>
			return Err(Error::Stf(format!("Error loading shard {:?}: Error: {:?}", shard, e))),
	};

	debug!("calling into STF to get state");
	Ok(Stf::get_state(&mut state, trusted_getter_signed.into()))
}

/// Execute pending trusted operations for all shards until the [`max_exec_duration`] is reached.
///
/// For fairness, the [`max_exec_duration`] is split equally among all shards. Leftover time from
/// the previous shard is evenly distributed to all remaining shards.
fn exec_tops_for_all_shards<PB, SB, O, T>(
	ocall_api: &O,
	top_pool_getter: &T,
	latest_onchain_header: &PB::Header,
	max_exec_duration: Duration,
) -> Result<(Vec<OpaqueCall>, Vec<SB>)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	O: EnclaveOnChainOCallApi,
	T: GetTopPool,
{
	let shards = state::list_shards()?;
	let mut calls: Vec<OpaqueCall> = Vec::new();
	let mut signed_blocks: Vec<SB> = Vec::with_capacity(shards.len());
	let mut remaining_shards = shards.len() as u32;
	let ends_at = duration_now() + max_exec_duration;

	let pool_mutex = match top_pool_getter.get() {
		Some(mutex) => mutex,
		None => {
			error!("Could not get mutex to pool");
			return Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED).into()
		},
	};

	let tx_pool_guard = pool_mutex.lock().unwrap();
	let tx_pool = tx_pool_guard.deref();

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

		match exec_tops::<PB, SB, _, _>(
			ocall_api,
			tx_pool,
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

/// Execute pending trusted operations for the `shard` until the `max_exec_duration` is reached.
///
/// The first half of the `max_exec_duration` is dedicated to the trusted getters, the second half
/// (plus leftover time from the getters) to the trusted calls.
///
/// Todo: The getters should be handled individually: #400
fn exec_tops<PB, SB, O, P>(
	ocall_api: &O,
	top_pool: &P,
	latest_onchain_header: &PB::Header,
	shard: ShardIdentifier,
	max_exec_duration: Duration,
) -> Result<(Vec<OpaqueCall>, Option<SB>)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	O: EnclaveOnChainOCallApi,
	P: TrustedOperationPool<Hash = H256> + 'static,
{
	// first half of the slot is dedicated to getters.
	let ends_at = duration_now() + max_exec_duration;
	let remaining_getter_time = max_exec_duration / 2;

	exec_trusted_getters(top_pool, shard, remaining_getter_time)?;

	let remaining_call_time = match remaining_time(ends_at) {
		Some(t) => t,
		None => {
			info!("[Enclave] not executed trusted calls; no time left.");
			return Ok(Default::default())
		},
	};

	let (calls, blocks) = exec_trusted_calls::<PB, SB, _, _>(
		ocall_api,
		top_pool,
		latest_onchain_header,
		shard,
		remaining_call_time,
	)?;

	if blocks.is_none() {
		warn!("[Enclave] did not produce a block for shard {:?}", shard);
	}

	Ok((calls, blocks))
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
fn exec_trusted_calls<PB, SB, O, P>(
	on_chain_ocall: &O,
	top_pool: &P,
	latest_onchain_header: &PB::Header,
	shard: H256,
	max_exec_duration: Duration,
) -> Result<(Vec<OpaqueCall>, Option<SB>)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
	O: EnclaveOnChainOCallApi,
	P: TrustedOperationPool<Hash = H256> + 'static,
{
	let author = Author::new(Arc::new(top_pool));
	let ends_at = duration_now() + max_exec_duration;

	let mut calls = Vec::<OpaqueCall>::new();
	let mut call_hashes = Vec::<H256>::new();

	// load state before executing any calls
	let mut state = load_initialized_state(&shard)?;
	// save the state hash before call executions
	// (needed for block composition)
	trace!("Getting hash of previous state ..");
	let prev_state_hash = state::hash_of(state.state.clone())?;
	trace!("Loaded hash of previous state: {:?}", prev_state_hash);

	// retrieve trusted operations from pool
	let trusted_calls = author.get_pending_tops_separated(shard)?.0;

	debug!("Got following trusted calls from pool: {:?}", trusted_calls);
	// call execution
	for trusted_call_signed in trusted_calls.into_iter() {
		match handle_trusted_worker_call::<PB, _>(
			&mut calls,
			&mut state,
			&trusted_call_signed,
			latest_onchain_header,
			shard,
			on_chain_ocall,
		) {
			Ok(hashes) => {
				if let Some((_, op_hash)) = hashes {
					call_hashes.push(op_hash)
				}
				author
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
	let block = match compose_block_and_confirmation::<PB, SB>(
		latest_onchain_header,
		call_hashes,
		shard,
		prev_state_hash,
		&mut state,
	) {
		Ok((block_confirm, signed_block)) => {
			calls.push(block_confirm);

			// Notify watching clients of InSidechainBlock
			let block = signed_block.block();
			top_pool.on_block_created(block.signed_top_hashes(), block.hash());

			Some(signed_block)
		},
		Err(e) => {
			error!("Could not compose block confirmation: {:?}", e);
			None
		},
	};
	// save updated state after call executions
	let _new_state_hash = state::write(state, &shard)?;

	Ok((calls, block))
}

fn load_initialized_state(shard: &H256) -> SgxResult<State> {
	trace!("Loading state from shard {:?}", shard);
	let state = if state::exists(&shard) {
		state::load(&shard)?
	} else {
		state::init_shard(&shard)?;
		Stf::init_state()
	};
	trace!("Sucessfully loaded or initialized state from shard {:?}", shard);
	Ok(state)
}

/// Execute pending trusted getters for the `shard` until `max_exec_duration` is reached.
fn exec_trusted_getters<P>(top_pool: &P, shard: H256, max_exec_duration: Duration) -> Result<()>
where
	P: TrustedOperationPool<Hash = H256> + 'static,
{
	let author = Author::new(Arc::new(top_pool));
	let ends_at = duration_now() + max_exec_duration;

	// retrieve trusted operations from pool
	let trusted_getters = author.get_pending_tops_separated(shard)?.1;
	for trusted_getter_signed in trusted_getters.into_iter() {
		let hash_of_getter = author.hash_of(&trusted_getter_signed.clone().into());

		// get state
		match get_stf_state(trusted_getter_signed, shard) {
			Ok(r) => {
				trace!("Successfully loaded stf state");
				// let client know of current state
				trace!("Updating client");
				match top_pool.rpc_send_state(hash_of_getter, r.encode()) {
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
			author.remove_top(vec![TrustedOperationOrHash::Hash(hash_of_getter)], shard, false)
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

/// Composes a sidechain block of a shard
pub fn compose_block_and_confirmation<PB, SB>(
	latest_onchain_header: &PB::Header,
	top_call_hashes: Vec<H256>,
	shard: ShardIdentifier,
	state_hash_apriori: H256,
	state: &mut StfState,
) -> Result<(OpaqueCall, SB)>
where
	PB: BlockT<Hash = H256>,
	SB: SignedBlockT<Public = sp_core::ed25519::Public, Signature = MultiSignature>,
	SB::Block: SidechainBlockT<ShardIdentifier = H256, Public = sp_core::ed25519::Public>,
{
	let signer_pair = Ed25519Seal::unseal()?;
	let layer_one_head = latest_onchain_header.hash();

	let block_number = Stf::get_sidechain_block_number(state)
		.map(|n| n + 1)
		.ok_or(Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED))?;

	Stf::update_sidechain_block_number(state, block_number);

	let parent_hash =
		Stf::get_last_block_hash(state).ok_or(Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED))?;

	// hash previous of state
	let state_hash_aposteriori = state::hash_of(state.state.clone())?;

	// create encrypted payload
	let mut payload: Vec<u8> =
		StatePayload::new(state_hash_apriori, state_hash_aposteriori, state.state_diff.clone())
			.encode();
	AesSeal::unseal().map(|key| key.encrypt(&mut payload))??;

	let block = SB::Block::new(
		signer_pair.public(),
		block_number,
		parent_hash,
		layer_one_head,
		shard,
		top_call_hashes,
		payload,
		SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
	);

	let block_hash = blake2_256(&block.encode());
	let signed_block = block.sign_block(&signer_pair);

	debug!("Block hash 0x{}", hex::encode_hex(&block_hash));
	Stf::update_last_block_hash(state, block_hash.into());

	let xt_block = [TEEREX_MODULE, BLOCK_CONFIRMED];
	let opaque_call =
		OpaqueCall::from_tuple(&(xt_block, shard, block_hash, state_hash_aposteriori.encode()));
	Ok((opaque_call, signed_block))
}

pub fn update_states<PB, O>(header: PB::Header, on_chain_ocall_api: &O) -> Result<()>
where
	PB: BlockT<Hash = H256>,
	O: EnclaveOnChainOCallApi,
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

				for s in shards {
					if !state::exists(&s) {
						info!("Initialized new shard that was found on chain: {:?}", s);
						state::init_shard(&s)?;
					}
					// per shard (cid) requests
					let per_shard_hashes = storage_hashes_to_update_per_shard(&s);
					let per_shard_update = on_chain_ocall_api
						.get_multiple_storages_verified(per_shard_hashes, &header)
						.map(into_map)?;

					let mut state = state::load(&s)?;
					trace!("Sucessfully loaded state, updating states ...");
					Stf::update_storage(&mut state, &per_shard_update.into());
					Stf::update_storage(&mut state, &state_diff_update);

					// block number is purged from the substrate state so it can't be read like other storage values
					// The number conversion is a bit unfortunate, but I wanted to prevent making the stf generic for now
					Stf::update_layer_one_block_number(
						&mut state,
						(*header.number()).unique_saturated_into(),
					);

					state::write(state, &s)?;
				}
			},
			None => info!("No shards are on the chain yet"),
		};
	};
	Ok(())
}

/// Scans blocks for extrinsics that ask the enclave to execute some actions.
/// Executes indirect invocation calls, as well as shielding and unshielding calls
/// Returns all unshielding call confirmations as opaque calls
pub fn scan_block_for_relevant_xt<PB, O>(block: &PB, on_chain_ocall: &O) -> Result<Vec<OpaqueCall>>
where
	PB: BlockT<Hash = H256>,
	O: EnclaveOnChainOCallApi,
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
				if let Err(e) = handle_shield_funds_xt(&mut opaque_calls, xt) {
					error!("Error performing shieldfunds. Error: {:?}", e);
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
					let mut state = load_initialized_state(&shard)?;
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
					trace!("Updating state of shard {:?}", shard);
					state::write(state, &shard)?;
				}
			}
		}
	}

	Ok(opaque_calls)
}

fn handle_shield_funds_xt(
	calls: &mut Vec<OpaqueCall>,
	xt: UncheckedExtrinsicV4<ShieldFundsFn>,
) -> Result<()> {
	let (call, account_encrypted, amount, shard) = xt.function.clone();
	info!("Found ShieldFunds extrinsic in block: \nCall: {:?} \nAccount Encrypted {:?} \nAmount: {} \nShard: {}",
        call, account_encrypted, amount, shard.encode().to_base58(),
    );

	let mut state = load_initialized_state(&shard)?;

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

	let state_hash = state::write(state, &shard)?;

	let xt_call = [TEEREX_MODULE, CALL_CONFIRMED];
	let call_hash = blake2_256(&xt.encode());
	debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

	calls.push(OpaqueCall::from_tuple(&(xt_call, shard, call_hash, state_hash.encode())));

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
	O: EnclaveOnChainOCallApi,
{
	debug!("query mrenclave of self");
	let mrenclave = OcallApi.get_mrenclave_of_self()?;
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
	debug!("Operation hash 0x{}", hex::encode_hex(&operation_hash));
	debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

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
