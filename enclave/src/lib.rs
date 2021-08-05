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
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]
#![crate_name = "substratee_worker_enclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![allow(clippy::missing_safety_doc)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use crate::{
	error::{Error, Result},
	ocall::{
		ocall_component_factory::{OCallComponentFactory, OCallComponentFactoryTrait},
		rpc_ocall::EnclaveRpcOCall,
	},
	onchain::storage::GetOnchainStorage,
	utils::{hash_from_slice, UnwrapOrSgxErrorUnexpected},
};
use base58::ToBase58;
use chain_relay::{Block, Header, Validator};
use codec::{alloc::string::String, Decode, Encode};
use core::ops::Deref;
use log::*;
use rpc::{
	api::SideChainApi,
	author::{hash::TrustedOperationOrHash, Author, AuthorApi},
	basic_pool::BasicPool,
};
use sgx_externalities::SgxExternalitiesTypeTrait;
use sgx_types::{sgx_status_t, SgxResult};
use sp_core::{blake2_256, crypto::Pair, H256};
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::{generic::SignedBlock, traits::Header as HeaderT, OpaqueExtrinsic};
use std::{
	borrow::ToOwned,
	collections::HashMap,
	slice,
	sync::{Arc, SgxMutex, SgxMutexGuard},
	time::{SystemTime, UNIX_EPOCH},
	untrusted::time::SystemTimeEx,
	vec::Vec,
};
use substrate_api_client::{
	compose_extrinsic_offline, extrinsic::xt_primitives::UncheckedExtrinsicV4,
};
use substratee_node_primitives::{CallWorkerFn, ShieldFundsFn};
use substratee_ocall_api::{
	EnclaveAttestationOCallApi, EnclaveOnChainOCallApi, EnclaveRpcOCallApi,
};
use substratee_settings::{
	enclave::{CALL_TIMEOUT, GETTER_TIMEOUT},
	node::{
		BLOCK_CONFIRMED, CALL_CONFIRMED, CALL_WORKER, REGISTER_ENCLAVE, RUNTIME_SPEC_VERSION,
		RUNTIME_TRANSACTION_VERSION, SHIELD_FUNDS, SUBSTRATEE_REGISTRY_MODULE,
	},
};
use substratee_stf::{
	stf_sgx::OpaqueCall,
	stf_sgx_primitives::{shards_key_hash, storage_hashes_to_update_per_shard},
	AccountId, Getter, ShardIdentifier, State as StfState, State, StatePayload, Stf, TrustedCall,
	TrustedCallSigned, TrustedGetterSigned,
};
use substratee_storage::{StorageEntryVerified, StorageProof};
use substratee_worker_primitives::{
	block::{Block as SidechainBlock, SignedBlock as SignedSidechainBlock},
	BlockHash,
};
use utils::write_slice_and_whitespace_pad;

mod aes;
mod attestation;
mod ed25519;
mod io;
mod ipfs;
mod ocall;
mod rsa3072;
mod state;
mod utils;

pub mod cert;
pub mod error;
pub mod hex;
pub mod onchain;
pub mod rpc;
pub mod sidechain;
pub mod tls_ra;
pub mod top_pool;

#[cfg(feature = "test")]
pub mod test;

#[cfg(feature = "test")]
pub mod tests;

#[cfg(not(feature = "test"))]
use sgx_types::size_t;

// this is a 'dummy' for production mode
#[cfg(not(feature = "test"))]
#[no_mangle]
pub extern "C" fn test_main_entrance() -> size_t {
	unreachable!("Tests are not available when compiled in production mode.")
}

pub const CERTEXPIRYDAYS: i64 = 90i64;

#[derive(Debug, Clone, PartialEq)]
pub enum Timeout {
	Call,
	Getter,
}

pub type Hash = sp_core::H256;
type BPool = BasicPool<SideChainApi<Block>, Block, EnclaveRpcOCall>;

#[no_mangle]
pub unsafe extern "C" fn init() -> sgx_status_t {
	// initialize the logging environment in the enclave
	env_logger::init();

	if let Err(status) = ed25519::create_sealed_if_absent() {
		return status
	}

	let signer = match ed25519::unseal_pair() {
		Ok(pair) => pair,
		Err(status) => return status,
	};
	info!("[Enclave initialized] Ed25519 prim raw : {:?}", signer.public().0);

	if let Err(e) = rsa3072::create_sealed_if_absent() {
		return e.into()
	}

	// create the aes key that is used for state encryption such that a key is always present in tests.
	// It will be overwritten anyway if mutual remote attastation is performed with the primary worker
	if let Err(status) = aes::create_sealed_if_absent() {
		return status
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
	let rsa_pubkey = match rsa3072::unseal_pubkey() {
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
	if let Err(status) = ed25519::create_sealed_if_absent() {
		return status
	}

	let signer = match ed25519::unseal_pair() {
		Ok(pair) => pair,
		Err(status) => return status,
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

	let ocall_api = OCallComponentFactory::attestation_api();

	let signer = ed25519::unseal_pair().unwrap();
	let call = (
		[SUBSTRATEE_REGISTRY_MODULE, REGISTER_ENCLAVE],
		ocall_api
			.get_mrenclave_of_self()
			.map_or_else(|_| Vec::<u8>::new(), |m| m.m.encode()),
		url,
	);

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

fn create_extrinsics<V>(
	validator: &V,
	calls_buffer: Vec<OpaqueCall>,
	mut nonce: u32,
) -> Result<Vec<Vec<u8>>>
where
	V: Validator,
{
	// get information for composing the extrinsic
	let signer = ed25519::unseal_pair()?;
	debug!("Restored ECC pubkey: {:?}", signer.public());

	let extrinsics_buffer: Vec<Vec<u8>> = calls_buffer
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
			return e
		}
	}

	let mut state = match state::load(&shard) {
		Ok(s) => s,
		Err(status) => return status,
	};

	debug!("calling into STF to get state");
	let value_opt = Stf::get_state(&mut state, getter);

	debug!("returning getter result");
	write_slice_and_whitespace_pad(value_slice, value_opt.encode());

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn init_chain_relay(
	genesis_header: *const u8,
	genesis_header_size: usize,
	authority_list: *const u8,
	authority_list_size: usize,
	authority_proof: *const u8,
	authority_proof_size: usize,
	latest_header: *mut u8,
	latest_header_size: usize,
) -> sgx_status_t {
	info!("Initializing Chain Relay!");

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

	match io::light_validation::read_or_init_validator(header, auth, proof) {
		Ok(header) => write_slice_and_whitespace_pad(latest_header_slice, header.encode()),
		Err(e) => return e,
	}
	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn produce_blocks(
	blocks_to_sync: *const u8,
	blocks_to_sync_size: usize,
	nonce: *const u32,
) -> sgx_status_t {
	let mut blocks_to_sync_slice = slice::from_raw_parts(blocks_to_sync, blocks_to_sync_size);

	let blocks_to_sync: Vec<SignedBlock<Block>> = match Decode::decode(&mut blocks_to_sync_slice) {
		Ok(b) => b,
		Err(e) => {
			error!("Decoding signed blocks failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let mut validator = match io::light_validation::unseal() {
		Ok(v) => v,
		Err(e) => return e,
	};

	let on_chain_ocall_api = OCallComponentFactory::on_chain_api();

	let mut calls = match sync_blocks_on_chain_relay(
		blocks_to_sync,
		&mut validator,
		on_chain_ocall_api.as_ref(),
	) {
		Ok(c) => c,
		Err(e) => return e,
	};

	// get header of last block
	let latest_onchain_header: Header =
		validator.latest_finalized_header(validator.num_relays()).unwrap();

	// execute pending calls from operation pool and create block
	// (one per shard) as opaque call with block confirmation
	let rpc_ocall_api = OCallComponentFactory::rpc_api();
	let signed_blocks: Vec<SignedSidechainBlock> = match execute_top_pool_calls(
		rpc_ocall_api.as_ref(),
		on_chain_ocall_api.as_ref(),
		latest_onchain_header,
	) {
		Ok((confirm_calls, signed_blocks)) => {
			calls.extend(confirm_calls.into_iter());
			signed_blocks
		},
		Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	let extrinsics = match create_extrinsics(&validator, calls, *nonce) {
		Ok(xt) => xt,
		Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
	};

	// store extrinsics in chain relay for finalization check
	for xt in extrinsics.iter() {
		validator
			.submit_xt_to_be_included(
				validator.num_relays(),
				OpaqueExtrinsic::from_bytes(xt.as_slice()).unwrap(),
			)
			.unwrap();
	}

	if io::light_validation::seal(validator).is_err() {
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	};

	// ocall to worker to store signed block and send block confirmation
	// send extrinsics to layer 1 block chain, gossip blocks to side-chain
	if let Err(e) = on_chain_ocall_api.send_block_and_confirmation(extrinsics, signed_blocks) {
		error!("Failed to send block and confirmation: {}", e);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}

	sgx_status_t::SGX_SUCCESS
}

fn sync_blocks_on_chain_relay<V, O>(
	blocks_to_sync: Vec<SignedBlock<Block>>,
	validator: &mut V,
	on_chain_ocall_api: &O,
) -> SgxResult<Vec<OpaqueCall>>
where
	V: Validator,
	O: EnclaveOnChainOCallApi,
{
	let mut calls = Vec::<OpaqueCall>::new();

	debug!("Syncing chain relay!");
	for signed_block in blocks_to_sync.into_iter() {
		validator
			.check_xt_inclusion(validator.num_relays(), &signed_block.block)
			.unwrap(); // panic can only happen if relay_id does not exist

		if let Err(e) = validator.submit_simple_header(
			validator.num_relays(),
			signed_block.block.header.clone(),
			signed_block.justifications.clone(),
		) {
			error!("Block verification failed. Error : {:?}", e);
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		if update_states(signed_block.block.header.clone(), on_chain_ocall_api).is_err() {
			error!("Error performing state updates upon block import");
			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		}

		// execute indirect calls, incl. shielding and unshielding
		match scan_block_for_relevant_xt(&signed_block.block, on_chain_ocall_api) {
			// push shield funds to opaque calls
			Ok(c) => calls.extend(c.into_iter()),
			Err(_) => error!("Error executing relevant extrinsics"),
		};

		// compose indirect block confirmation
		let xt_block = [SUBSTRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED];
		let genesis_hash = validator.genesis_hash(validator.num_relays()).unwrap();
		let block_hash = signed_block.block.header.hash();
		let prev_state_hash = signed_block.block.header.parent_hash();
		calls.push(OpaqueCall(
			(xt_block, genesis_hash, block_hash, prev_state_hash.encode()).encode(),
		));
	}

	Ok(calls)
}

fn get_stf_state(
	trusted_getter_signed: TrustedGetterSigned,
	shard: ShardIdentifier,
) -> Option<Vec<u8>> {
	debug!("verifying signature of TrustedGetterSigned");
	if let false = trusted_getter_signed.verify_signature() {
		error!("bad signature");
		return None
	}

	if !state::exists(&shard) {
		info!("Initialized new shard that was queried chain: {:?}", shard);
		if let Err(e) = state::init_shard(&shard) {
			error!("Error initialising shard {:?} state: Error: {:?}", shard, e);
			return None
		}
	}

	let mut state = match state::load(&shard) {
		Ok(s) => s,
		Err(e) => {
			error!("Error loading shard {:?}: Error: {:?}", shard, e);
			return None
		},
	};

	debug!("calling into STF to get state");
	Stf::get_state(&mut state, trusted_getter_signed.into())
}

fn execute_top_pool_calls<R, O>(
	rpc_ocall: &R,
	on_chain_ocall: &O,
	latest_onchain_header: Header,
) -> Result<(Vec<OpaqueCall>, Vec<SignedSidechainBlock>)>
where
	R: EnclaveRpcOCallApi,
	O: EnclaveOnChainOCallApi,
{
	debug!("Executing pending pool operations");

	// load top pool
	let pool_mutex: &SgxMutex<BPool> = match rpc::worker_api_direct::load_top_pool() {
		Some(mutex) => mutex,
		None => {
			error!("Could not get mutex to pool");
			return Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED).into()
		},
	};

	let pool_guard: SgxMutexGuard<BPool> = pool_mutex.lock().unwrap();
	let pool: Arc<&BPool> = Arc::new(pool_guard.deref());
	let author: Arc<Author<&BPool>> = Arc::new(Author::new(pool.clone()));

	// get all shards
	let shards = state::list_shards()?;

	// Handle trusted getters
	execute_trusted_getters(rpc_ocall, &author, &shards)?;

	// Handle trusted calls
	let calls_and_blocks =
		execute_trusted_calls(on_chain_ocall, latest_onchain_header, pool, author, shards)?;

	Ok(calls_and_blocks)
}

fn execute_trusted_calls<O>(
	on_chain_ocall: &O,
	latest_onchain_header: Header,
	pool: Arc<&BPool>,
	author: Arc<Author<&BPool>>,
	shards: Vec<H256>,
) -> Result<(Vec<OpaqueCall>, Vec<SignedSidechainBlock>)>
where
	O: EnclaveOnChainOCallApi,
{
	let mut calls = Vec::<OpaqueCall>::new();
	let mut blocks = Vec::<SignedSidechainBlock>::new();
	let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	let mut is_done = false;
	for shard in shards.into_iter() {
		let mut call_hashes = Vec::<H256>::new();

		// load state before executing any calls
		let mut state = load_initialized_state(&shard)?;
		// save the state hash before call executions
		// (needed for block composition)
		let prev_state_hash = state::hash_of(state.state.clone())?;

		// retrieve trusted operations from pool
		let trusted_calls = author.get_pending_tops_separated(shard)?.0;

		debug!("Got following trusted calls from pool: {:?}", trusted_calls);
		// call execution
		for trusted_call_signed in trusted_calls.into_iter() {
			match handle_trusted_worker_call(
				&mut calls,
				&mut state,
				&trusted_call_signed,
				latest_onchain_header.clone(),
				shard,
				on_chain_ocall,
			) {
				Ok(hashes) => {
					let inblock = match hashes {
						Some((_, operation_hash)) => {
							call_hashes.push(operation_hash);
							true
						},
						None => {
							// remove call as invalid from pool
							false
						},
					};

					// TODO: prune instead of remove_top ? Block needs to be known
					// TODO: move this pruning to after finalization confirmations, not here!
					// remove calls from pool (either as valid or invalid)
					author
						.remove_top(
							vec![TrustedOperationOrHash::Operation(
								trusted_call_signed.into_trusted_operation(true),
							)],
							shard,
							inblock,
						)
						.unwrap();
				},
				Err(e) =>
					error!("Error performing worker call (will not push top hash): Error: {:?}", e),
			};
			// Check time
			if time_is_overdue(Timeout::Call, start_time) {
				is_done = true;
				break
			}
		}
		// create new block (side-chain)
		match compose_block_and_confirmation(
			latest_onchain_header.clone(),
			call_hashes,
			shard,
			prev_state_hash,
			&mut state,
		) {
			Ok((block_confirm, signed_block)) => {
				calls.push(block_confirm);
				blocks.push(signed_block.clone());

				// Notify watching clients of InSidechainBlock
				let composed_block = signed_block.block();
				let block_hash: BlockHash = blake2_256(&composed_block.encode()).into();
				pool.pool()
					.validated_pool()
					.on_block_created(composed_block.signed_top_hashes(), block_hash);
			},
			Err(e) => error!("Could not compose block confirmation: {:?}", e),
		}
		// save updated state after call executions
		let _new_state_hash = state::write(state.clone(), &shard)?;

		if is_done {
			break
		}
	}

	Ok((calls, blocks))
}

fn load_initialized_state(shard: &H256) -> SgxResult<State> {
	let state = if state::exists(&shard) {
		state::load(&shard)?
	} else {
		state::init_shard(&shard)?;
		Stf::init_state()
	};
	Ok(state)
}

fn execute_trusted_getters<R>(
	rpc_ocall: &R,
	author: &Arc<Author<&BPool>>,
	shards: &[H256],
) -> Result<()>
where
	R: EnclaveRpcOCallApi,
{
	let start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	let mut is_done = false;
	for shard in shards.to_owned().into_iter() {
		// retrieve trusted operations from pool
		let trusted_getters = author.get_pending_tops_separated(shard)?.1;
		for trusted_getter_signed in trusted_getters.into_iter() {
			// get state
			let value_opt = get_stf_state(trusted_getter_signed.clone(), shard);
			// get hash
			let hash_of_getter = author.hash_of(&trusted_getter_signed.into());
			// let client know of current state
			if rpc_ocall.send_state(hash_of_getter, value_opt).is_err() {
				error!("Could not get state from stf");
			}
			// remove getter from pool
			if let Err(e) =
				author.remove_top(vec![TrustedOperationOrHash::Hash(hash_of_getter)], shard, false)
			{
				error!("Error removing trusted operation from top pool: Error: {:?}", e);
			}
			// Check time
			if time_is_overdue(Timeout::Getter, start_time) {
				is_done = true;
				break
			}
		}
		if is_done {
			break
		}
	}

	Ok(())
}

/// Checks if the time of call execution or getter is overdue
/// Returns true if specified time is exceeded
pub fn time_is_overdue(timeout: Timeout, start_time: i64) -> bool {
	let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
	let max_time_ms: i64 = match timeout {
		Timeout::Call => CALL_TIMEOUT,
		Timeout::Getter => GETTER_TIMEOUT,
	};
	(now - start_time) * 1000 >= max_time_ms
}

/// Composes a sidechain block of a shard
pub fn compose_block_and_confirmation(
	latest_onchain_header: Header,
	top_call_hashes: Vec<H256>,
	shard: ShardIdentifier,
	state_hash_apriori: H256,
	state: &mut StfState,
) -> Result<(OpaqueCall, SignedSidechainBlock)> {
	let signer_pair = ed25519::unseal_pair()?;
	let layer_one_head = latest_onchain_header.hash();

	let block_number = Stf::get_sidechain_block_number(state)
		.map(|n| n + 1)
		.ok_or(Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED))?;

	Stf::update_sidechain_block_number(state, block_number);

	let block_number: u64 = block_number; //FIXME! Should be either u64 or u32! Not both..
	let parent_hash =
		Stf::get_last_block_hash(state).ok_or(Error::Sgx(sgx_status_t::SGX_ERROR_UNEXPECTED))?;

	// hash previous of state
	let state_hash_aposteriori = state::hash_of(state.state.clone())?;
	let state_update = state.state_diff.clone().encode();

	// create encrypted payload
	let mut payload: Vec<u8> =
		StatePayload::new(state_hash_apriori, state_hash_aposteriori, state_update).encode();
	aes::de_or_encrypt(&mut payload)?;

	let block = SidechainBlock::construct_block(
		signer_pair.public().into(),
		block_number,
		parent_hash,
		layer_one_head,
		shard,
		top_call_hashes,
		payload,
		SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64,
	);

	let signed_block = block.sign(&signer_pair);

	let block_hash = blake2_256(&block.encode());
	debug!("Block hash 0x{}", hex::encode_hex(&block_hash));
	Stf::update_last_block_hash(state, block_hash.into());

	let xt_block = [SUBSTRATEE_REGISTRY_MODULE, BLOCK_CONFIRMED];
	let opaque_call =
		OpaqueCall((xt_block, shard, block_hash, state_hash_aposteriori.encode()).encode());
	Ok((opaque_call, signed_block))
}

pub fn update_states<O>(header: Header, on_chain_ocall_api: &O) -> Result<()>
where
	O: EnclaveOnChainOCallApi,
{
	debug!("Update STF storage upon block import!");
	let storage_hashes = Stf::storage_hashes_to_update_on_block();

	if storage_hashes.is_empty() {
		return Ok(())
	}

	// global requests they are the same for every shard
	let update_map = on_chain_ocall_api
		.get_multiple_onchain_storages(storage_hashes, &header)
		.map(into_map)?;

	// look for new shards an initialize them
	if let Some(maybe_shards) = update_map.get(&shards_key_hash()) {
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
					let per_shard_update_map = on_chain_ocall_api
						.get_multiple_onchain_storages(per_shard_hashes, &header)
						.map(into_map)?;

					let mut state = state::load(&s)?;
					Stf::update_storage(&mut state, &per_shard_update_map);
					Stf::update_storage(&mut state, &update_map);

					// block number is purged from the substrate state so it can't be read like other storage values
					Stf::update_layer_one_block_number(&mut state, header.number);

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
pub fn scan_block_for_relevant_xt<O>(block: &Block, on_chain_ocall: &O) -> Result<Vec<OpaqueCall>>
where
	O: EnclaveOnChainOCallApi,
{
	debug!("Scanning block {} for relevant xt", block.header.number());
	let mut opaque_calls = Vec::<OpaqueCall>::new();
	for xt_opaque in block.extrinsics.iter() {
		// shield funds XT
		if let Ok(xt) =
			UncheckedExtrinsicV4::<ShieldFundsFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			// confirm call decodes successfully as well
			if xt.function.0 == [SUBSTRATEE_REGISTRY_MODULE, SHIELD_FUNDS] {
				if let Err(e) = handle_shield_funds_xt(&mut opaque_calls, xt) {
					error!("Error performing shieldfunds. Error: {:?}", e);
				}
			}
		};

		// call worker XT
		if let Ok(xt) =
			UncheckedExtrinsicV4::<CallWorkerFn>::decode(&mut xt_opaque.encode().as_slice())
		{
			if xt.function.0 == [SUBSTRATEE_REGISTRY_MODULE, CALL_WORKER] {
				if let Ok((decrypted_trusted_call, shard)) = decrypt_unchecked_extrinsic(xt) {
					// load state before executing any calls
					let mut state = load_initialized_state(&shard)?;
					// call execution
					if let Err(e) = handle_trusted_worker_call(
						&mut opaque_calls, // necessary for unshielding
						&mut state,
						&decrypted_trusted_call,
						block.header.clone(),
						shard,
						on_chain_ocall,
					) {
						error!("Error performing worker call: Error: {:?}", e);
					}
					// save updated state
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
	let rsa_keypair = rsa3072::unseal_pair()?;
	let account_vec = rsa3072::decrypt(&account_encrypted, &rsa_keypair)?;
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

	let xt_call = [SUBSTRATEE_REGISTRY_MODULE, CALL_CONFIRMED];
	let call_hash = blake2_256(&xt.encode());
	debug!("Call hash 0x{}", hex::encode_hex(&call_hash));

	calls.push(OpaqueCall((xt_call, shard, call_hash, state_hash.encode()).encode()));

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
	let rsa_keypair = rsa3072::unseal_pair()?;
	let request_vec = rsa3072::decrypt(&cyphertext, &rsa_keypair)?;

	Ok(TrustedCallSigned::decode(&mut request_vec.as_slice()).map(|call| (call, shard))?)
}

fn handle_trusted_worker_call<O>(
	calls: &mut Vec<OpaqueCall>,
	state: &mut StfState,
	stf_call_signed: &TrustedCallSigned,
	header: Header,
	shard: ShardIdentifier,
	on_chain_ocall_api: &O,
) -> Result<Option<(H256, H256)>>
where
	O: EnclaveOnChainOCallApi,
{
	debug!("query mrenclave of self");
	let ocall_api = OCallComponentFactory::attestation_api();
	let mrenclave = ocall_api.get_mrenclave_of_self()?;
	debug!("MRENCLAVE of self is {}", mrenclave.m.to_base58());

	if let false = stf_call_signed.verify_signature(&mrenclave.m, &shard) {
		error!("TrustedCallSigned: bad signature");
		// do not panic here or users will be able to shoot workers dead by supplying a bad signature
		return Ok(None)
	}

	// Necessary because chain relay sync may not be up to date
	// see issue #208
	debug!("Update STF storage!");
	let storage_hashes = Stf::get_storage_hashes_to_update(&stf_call_signed);
	let update_map = on_chain_ocall_api
		.get_multiple_onchain_storages(storage_hashes, &header)
		.map(into_map)?;
	Stf::update_storage(state, &update_map);

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
