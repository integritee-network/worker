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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(feature = "std")]
use rust_base58::base58::FromBase58;

#[cfg(feature = "sgx")]
use base58::FromBase58;

use codec::{Decode, Encode};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{
	DirectRequestStatus, Request, RpcReturnValue, ShardIdentifier, TrustedOperationStatus,
};
use jsonrpc_core::{
	futures::executor, serde_json::json, Error as RpcError, IoHandler, Params, Value,
};
use std::{borrow::ToOwned, format, string::String, sync::Arc, vec, vec::Vec};

type Hash = sp_core::H256;

pub fn add_top_pool_direct_rpc_methods<R>(
	top_pool_author: Arc<R>,
	mut io_handler: IoHandler,
) -> IoHandler
where
	R: AuthorApi<Hash, Hash> + Send + Sync + 'static,
{
	// author_submitAndWatchExtrinsic
	let author_submit_and_watch_extrinsic_name: &str = "author_submitAndWatchExtrinsic";
	let submit_watch_author = top_pool_author.clone();
	io_handler.add_sync_method(author_submit_and_watch_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<u8>>() {
			Ok(encoded_params) => match Request::decode(&mut encoded_params.as_slice()) {
				Ok(request) => {
					let shard: ShardIdentifier = request.shard;
					let encrypted_trusted_call: Vec<u8> = request.cyphertext;
					let result = async {
						submit_watch_author.watch_top(encrypted_trusted_call.clone(), shard).await
					};
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
						Err(rpc_error) => compute_encoded_return_error(rpc_error.message.as_str()),
					};
					Ok(json!(json_value))
				},
				Err(_) => Ok(json!(compute_encoded_return_error("Could not decode request"))),
			},
			Err(e) => {
				let error_msg: String = format!("Could not submit trusted call due to: {}", e);
				Ok(json!(compute_encoded_return_error(error_msg.as_str())))
			},
		}
	});

	// author_submitExtrinsic
	let author_submit_extrinsic_name: &str = "author_submitExtrinsic";
	let submit_author = top_pool_author.clone();
	io_handler.add_sync_method(author_submit_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<u8>>() {
			Ok(encoded_params) => match Request::decode(&mut encoded_params.as_slice()) {
				Ok(request) => {
					let shard: ShardIdentifier = request.shard;
					let encrypted_trusted_op: Vec<u8> = request.cyphertext;
					let result = async {
						submit_author.submit_top(encrypted_trusted_op.clone(), shard).await
					};
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
						Err(rpc_error) => compute_encoded_return_error(rpc_error.message.as_str()),
					};
					Ok(json!(json_value))
				},
				Err(_) => Ok(json!(compute_encoded_return_error("Could not decode request"))),
			},
			Err(e) => {
				let error_msg: String = format!("Could not submit trusted call due to: {}", e);
				Ok(json!(compute_encoded_return_error(error_msg.as_str())))
			},
		}
	});

	// author_pendingExtrinsics
	let author_pending_extrinsic_name: &str = "author_pendingExtrinsics";
	let pending_author = top_pool_author;
	io_handler.add_sync_method(author_pending_extrinsic_name, move |params: Params| {
		match params.parse::<Vec<String>>() {
			Ok(shards) => {
				let mut retrieved_operations = vec![];
				for shard_base58 in shards.iter() {
					let shard = match decode_shard_from_base58(shard_base58.as_str()) {
						Ok(id) => id,
						Err(msg) => return Ok(Value::String(msg)),
					};
					if let Ok(vec_of_operations) = pending_author.pending_tops(shard) {
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
				Ok(json!(compute_encoded_return_error(error_msg.as_str())))
			},
		}
	});

	io_handler
}

// converts the rpc methods vector to a string and adds commas and brackets for readability
fn decode_shard_from_base58(shard_base58: &str) -> Result<ShardIdentifier, String> {
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

fn compute_encoded_return_error(error_msg: &str) -> Vec<u8> {
	RpcReturnValue::from_error_message(error_msg).encode()
}
