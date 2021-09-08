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

pub extern crate alloc;
use alloc::{
	borrow::ToOwned,
	format,
	slice::{from_raw_parts, from_raw_parts_mut},
	str,
	string::String,
	vec::Vec,
};
use core::{ops::Deref, result::Result};

use sgx_types::*;
use std::sync::{
	atomic::{AtomicPtr, Ordering},
	Arc, SgxMutex,
};

use sp_core::H256 as Hash;

use codec::{Decode, Encode};
use log::*;

use crate::rpc::{
	api::SideChainApi,
	author::{Author, AuthorApi},
	basic_pool::BasicPool,
};

use crate::top_pool::pool::Options as PoolOptions;

use self::serde_json::*;
use jsonrpc_core::{futures::executor, Error as RpcError, *};

use ita_stf::ShardIdentifier;

use base58::FromBase58;

use itp_types::{
	block::SignedBlock, Block, DirectRequestStatus, Request, RpcReturnValue, TrustedOperationStatus,
};

use crate::{rsa3072, utils::write_slice_and_whitespace_pad, OcallApi};

static GLOBAL_TX_POOL: AtomicPtr<()> = AtomicPtr::new(0 as *mut ());

#[no_mangle]
// initialise tx pool and store within static atomic pointer
pub unsafe extern "C" fn initialize_pool() -> sgx_status_t {
	let api = Arc::new(SideChainApi::new());
	let tx_pool = BasicPool::create(PoolOptions::default(), api);
	let pool_ptr =
		Arc::new(SgxMutex::<BasicPool<SideChainApi<Block>, Block, OcallApi>>::new(tx_pool));
	let ptr = Arc::into_raw(pool_ptr);
	GLOBAL_TX_POOL.store(ptr as *mut (), Ordering::SeqCst);

	sgx_status_t::SGX_SUCCESS
}

pub fn load_top_pool() -> Option<&'static SgxMutex<BasicPool<SideChainApi<Block>, Block, OcallApi>>>
{
	let ptr = GLOBAL_TX_POOL.load(Ordering::SeqCst)
		as *mut SgxMutex<BasicPool<SideChainApi<Block>, Block, OcallApi>>;
	if ptr.is_null() {
		None
	} else {
		Some(unsafe { &*ptr })
	}
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn convert_vec_to_string(vec_methods: Vec<&str>) -> String {
	let mut method_string = String::new();
	for i in 0..vec_methods.len() {
		method_string.push_str(vec_methods[i]);
		if vec_methods.len() > (i + 1) {
			method_string.push_str(", ");
		}
	}
	format!("methods: [{}]", method_string)
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn decode_shard_from_base58(shard_base58: String) -> Result<ShardIdentifier, String> {
	let shard_vec = match shard_base58.from_base58() {
		Ok(vec) => vec,
		Err(_) => return Err("Invalid base58 format of shard id".to_owned()),
	};
	let shard = match ShardIdentifier::decode(&mut shard_vec.as_slice()) {
		Ok(hash) => hash,
		Err(_) => return Err("Shard ID is not of type H256".to_owned()),
	};
	Ok(shard)
}

fn compute_encoded_return_error(error_msg: String) -> Vec<u8> {
	let return_value = RpcReturnValue {
		value: error_msg.encode(),
		do_watch: false,
		status: DirectRequestStatus::Error,
	};
	return_value.encode()
}

fn init_io_handler() -> IoHandler {
	let mut io = IoHandler::new();
	let mut rpc_methods_vec: Vec<&str> = Vec::new();

	// Add rpc methods
	// author_submitAndWatchExtrinsic
	let author_submit_and_watch_extrinsic_name: &str = "author_submitAndWatchExtrinsic";
	rpc_methods_vec.push(author_submit_and_watch_extrinsic_name);
	io.add_sync_method(author_submit_and_watch_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<u8>>() {
			Ok(encoded_params) => {
				// Aquire lock
				let tx_pool_mutex = load_top_pool().unwrap();
				let tx_pool_guard = tx_pool_mutex.lock().unwrap();
				let tx_pool = Arc::new(tx_pool_guard.deref());
				let author = Author::new(tx_pool);

				match Request::decode(&mut encoded_params.as_slice()) {
					Ok(request) => {
						let shard: ShardIdentifier = request.shard;
						let encrypted_trusted_call: Vec<u8> = request.cyphertext;
						let result =
							async { author.watch_top(encrypted_trusted_call.clone(), shard).await };
						let response: Result<Hash, RpcError> = executor::block_on(result);
						let json_value = match response {
							Ok(hash_value) => RpcReturnValue {
								do_watch: true,
								value: hash_value.encode(),
								status: DirectRequestStatus::TrustedOperationStatus(
									TrustedOperationStatus::Submitted,
								),
							}
							.encode(),
							Err(rpc_error) => compute_encoded_return_error(rpc_error.message),
						};
						Ok(json!(json_value))
					},
					Err(_) => Ok(json!(compute_encoded_return_error(
						"Could not decode request".to_owned()
					))),
				}
			},
			Err(e) => {
				let error_msg: String = format!("Could not submit trusted call due to: {}", e);
				Ok(json!(compute_encoded_return_error(error_msg)))
			},
		}
	});

	// author_submitExtrinsic
	let author_submit_extrinsic_name: &str = "author_submitExtrinsic";
	rpc_methods_vec.push(author_submit_extrinsic_name);
	io.add_sync_method(author_submit_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<u8>>() {
			Ok(encoded_params) => {
				// Aquire lock
				let tx_pool_mutex = load_top_pool().unwrap();
				let tx_pool_guard = tx_pool_mutex.lock().unwrap();
				let tx_pool = Arc::new(tx_pool_guard.deref());
				let author = Author::new(tx_pool);

				match Request::decode(&mut encoded_params.as_slice()) {
					Ok(request) => {
						let shard: ShardIdentifier = request.shard;
						let encrypted_trusted_op: Vec<u8> = request.cyphertext;
						let result =
							async { author.submit_top(encrypted_trusted_op.clone(), shard).await };
						let response: Result<Hash, RpcError> = executor::block_on(result);
						let json_value = match response {
							Ok(hash_value) => RpcReturnValue {
								do_watch: false,
								value: hash_value.encode(),
								status: DirectRequestStatus::TrustedOperationStatus(
									TrustedOperationStatus::Submitted,
								),
							}
							.encode(),
							Err(rpc_error) => compute_encoded_return_error(rpc_error.message),
						};
						Ok(json!(json_value))
					},
					Err(_) => Ok(json!(compute_encoded_return_error(
						"Could not decode request".to_owned()
					))),
				}
			},
			Err(e) => {
				let error_msg: String = format!("Could not submit trusted call due to: {}", e);
				Ok(json!(compute_encoded_return_error(error_msg)))
			},
		}
	});

	// author_pendingExtrinsics
	let author_pending_extrinsic_name: &str = "author_pendingExtrinsics";
	rpc_methods_vec.push(author_pending_extrinsic_name);
	io.add_sync_method(author_pending_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<String>>() {
			Ok(shards) => {
				// Aquire tx_pool lock
				let tx_pool_mutex = load_top_pool().unwrap();
				let tx_pool_guard = tx_pool_mutex.lock().unwrap();
				let tx_pool = Arc::new(tx_pool_guard.deref());
				let author = Author::new(tx_pool);

				let mut retrieved_operations = vec![];
				for shard_base58 in shards.iter() {
					let shard = match decode_shard_from_base58(shard_base58.clone()) {
						Ok(id) => id,
						Err(msg) => return Ok(Value::String(msg)),
					};
					if let Ok(vec_of_operations) = author.pending_tops(shard) {
						retrieved_operations.push(vec_of_operations);
					}
				}
				let json_value = RpcReturnValue {
					do_watch: false,
					value: retrieved_operations.encode(),
					status: DirectRequestStatus::Ok,
				};
				Ok(json!(json_value.encode()))
			},
			Err(e) => {
				let error_msg: String = format!("Could not retrieve pending calls due to: {}", e);
				Ok(json!(compute_encoded_return_error(error_msg)))
			},
		}
	});

	// author_getShieldingKey
	let rsa_pubkey_name: &str = "author_getShieldingKey";
	rpc_methods_vec.push(rsa_pubkey_name);
	io.add_sync_method(rsa_pubkey_name, move |_: Params| {
		let rsa_pubkey = match rsa3072::unseal_pubkey() {
			Ok(key) => key,
			Err(status) => {
				let error_msg: String = format!("Could not get rsa pubkey due to: {}", status);
				return Ok(json!(compute_encoded_return_error(error_msg)))
			},
		};

		let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
			Ok(k) => k,
			Err(x) => {
				let error_msg: String =
					format!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
				return Ok(json!(compute_encoded_return_error(error_msg)))
			},
		};
		let json_value =
			RpcReturnValue::new(rsa_pubkey_json.encode(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.encode()))
	});

	// chain_subscribeAllHeads
	let chain_subscribe_all_heads_name: &str = "chain_subscribeAllHeads";
	rpc_methods_vec.push(chain_subscribe_all_heads_name);
	io.add_sync_method(chain_subscribe_all_heads_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// state_getMetadata
	let state_get_metadata_name: &str = "state_getMetadata";
	rpc_methods_vec.push(state_get_metadata_name);
	io.add_sync_method(state_get_metadata_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// state_getRuntimeVersion
	let state_get_runtime_version_name: &str = "state_getRuntimeVersion";
	rpc_methods_vec.push(state_get_runtime_version_name);
	io.add_sync_method(state_get_runtime_version_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// state_get
	let state_get_name: &str = "state_get";
	rpc_methods_vec.push(state_get_name);
	io.add_sync_method(state_get_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_health
	let state_health_name: &str = "system_health";
	rpc_methods_vec.push(state_health_name);
	io.add_sync_method(state_health_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_name
	let state_name_name: &str = "system_name";
	rpc_methods_vec.push(state_name_name);
	io.add_sync_method(state_name_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_version
	let state_version_name: &str = "system_version";
	rpc_methods_vec.push(state_version_name);
	io.add_sync_method(state_version_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	let sidechain_import_import_name: &str = "sidechain_importBlock";
	rpc_methods_vec.push(sidechain_import_import_name);
	io.add_sync_method(sidechain_import_import_name, |sidechain_blocks: Params| {
		// Todo: actually do something with the block, i.e., apply the state diff.
		// However, this requires importing the stf here. So, before doing that and increase
		// the size of init_io_handler even more, we should think about how we can do that more
		// modularized.
		debug!("sidechain_importBlock rpc. Params: {:?}", sidechain_blocks);
		let block_vec: Vec<u8> = sidechain_blocks.parse()?;
		let blocks: Vec<SignedBlock> = Decode::decode(&mut block_vec.as_slice()).map_err(|_| {
			jsonrpc_core::error::Error::invalid_params_with_details(
				"Could not decode Vec<SignedBlock>",
				block_vec,
			)
		})?;
		info!("sidechain_importBlock. Blocks: {:?}", blocks);
		Ok(Value::String("ok".to_owned()))
	});

	// returns all rpcs methods
	let rpc_methods_string: String = convert_vec_to_string(rpc_methods_vec);
	io.add_sync_method("rpc_methods", move |_: Params| {
		Ok(Value::String(rpc_methods_string.to_owned()))
	});

	io
}

#[no_mangle]
pub unsafe extern "C" fn call_rpc_methods(
	request: *const u8,
	request_len: u32,
	response: *mut u8,
	response_len: u32,
) -> sgx_status_t {
	// init
	let io = init_io_handler();
	// get request string
	let req: Vec<u8> = from_raw_parts(request, request_len as usize).to_vec();
	let request_string = match str::from_utf8(&req) {
		Ok(req) => req,
		Err(e) => {
			error!("Decoding Header failed. Error: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	// Rpc Response String
	let response_string = io.handle_request_sync(request_string).unwrap();

	// update response outside of enclave
	let response_slice = from_raw_parts_mut(response, response_len as usize);
	write_slice_and_whitespace_pad(response_slice, response_string.as_bytes().to_vec());
	sgx_status_t::SGX_SUCCESS
}

pub mod tests {
	use super::{alloc::string::ToString, init_io_handler};
	use std::string::String;

	fn rpc_response<T: ToString>(result: T) -> String {
		format!(r#"{{"jsonrpc":"2.0","result":{},"id":1}}"#, result.to_string())
	}

	pub fn sidechain_import_block_is_ok() {
		let io = init_io_handler();
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[4,0,0,0,0,0,0,0,0,228,0,145,188,97,251,138,131,108,29,6,107,10,152,67,29,148,190,114,167,223,169,197,163,93,228,76,169,171,80,15,209,101,11,211,96,0,0,0,0,83,52,167,255,37,229,185,231,38,66,122,3,55,139,5,190,125,85,94,177,190,99,22,149,92,97,154,30,142,89,24,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,220,52,23,213,5,142,196,180,80,62,12,18,234,26,10,137,190,32,15,233,137,34,66,61,67,52,1,79,166,176,238,0,0,0,175,124,84,84,32,238,162,224,130,203,26,66,7,121,44,59,196,200,100,31,173,226,165,106,187,135,223,149,30,46,191,95,116,203,205,102,100,85,82,74,158,197,166,218,181,130,119,127,162,134,227,129,118,85,123,76,21,113,90,1,160,77,110,15],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		assert_eq!(response_string, rpc_response("\"ok\""));
	}

	pub fn sidechain_import_block_returns_invalid_param_err() {
		let io = init_io_handler();
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":["SophisticatedInvalidParam"],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params: invalid type: string \"SophisticatedInvalidParam\", expected u8."},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}

	pub fn sidechain_import_block_returns_decode_err() {
		let io = init_io_handler();
		let enclave_req =
			r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[2],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: Could not decode Vec<SignedBlock>","data":"[2]"},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}
}
