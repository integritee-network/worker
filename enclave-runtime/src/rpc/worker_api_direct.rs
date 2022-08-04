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

use codec::Encode;
use core::result::Result;
use ita_sgx_runtime::Runtime;
use itp_primitives_cache::{GetPrimitives, GLOBAL_PRIMITIVES_CACHE};
use itp_rpc::RpcReturnValue;
use itp_sgx_crypto::Rsa3072Seal;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{DirectRequestStatus, H256};
use itp_utils::ToHexPrefixed;
use its_sidechain::rpc_handler::{direct_top_pool_api, import_block_api};
use jsonrpc_core::{serde_json::json, IoHandler, Params, Value};
use sidechain_primitives::types::block::SignedBlock;
use std::{borrow::ToOwned, format, str, string::String, sync::Arc, vec::Vec};

fn compute_hex_encoded_return_error(error_msg: &str) -> String {
	RpcReturnValue::from_error_message(error_msg).to_hex()
}

fn get_all_rpc_methods_string(io_handler: &IoHandler) -> String {
	let method_string = io_handler
		.iter()
		.map(|rp_tuple| rp_tuple.0.to_owned())
		.collect::<Vec<String>>()
		.join(", ");

	format!("methods: [{}]", method_string)
}

pub fn public_api_rpc_handler<R>(top_pool_author: Arc<R>) -> IoHandler
where
	R: AuthorApi<H256, H256> + Send + Sync + 'static,
{
	let io = IoHandler::new();

	// Add direct TOP pool rpc methods
	let mut io = direct_top_pool_api::add_top_pool_direct_rpc_methods(top_pool_author, io);

	// author_getShieldingKey
	let rsa_pubkey_name: &str = "author_getShieldingKey";
	io.add_sync_method(rsa_pubkey_name, move |_: Params| {
		let rsa_pubkey = match Rsa3072Seal::unseal_pubkey() {
			Ok(key) => key,
			Err(status) => {
				let error_msg: String = format!("Could not get rsa pubkey due to: {}", status);
				return Ok(json!(compute_hex_encoded_return_error(error_msg.as_str())))
			},
		};

		let rsa_pubkey_json = match serde_json::to_string(&rsa_pubkey) {
			Ok(k) => k,
			Err(x) => {
				let error_msg: String =
					format!("[Enclave] can't serialize rsa_pubkey {:?} {}", rsa_pubkey, x);
				return Ok(json!(compute_hex_encoded_return_error(error_msg.as_str())))
			},
		};
		let json_value =
			RpcReturnValue::new(rsa_pubkey_json.encode(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	let mu_ra_url_name: &str = "author_getMuRaUrl";
	io.add_sync_method(mu_ra_url_name, move |_: Params| {
		let url = match GLOBAL_PRIMITIVES_CACHE.get_mu_ra_url() {
			Ok(url) => url,
			Err(status) => {
				let error_msg: String = format!("Could not get mu ra url due to: {}", status);
				return Ok(json!(compute_hex_encoded_return_error(error_msg.as_str())))
			},
		};

		let json_value = RpcReturnValue::new(url.encode(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	let untrusted_url_name: &str = "author_getUntrustedUrl";
	io.add_sync_method(untrusted_url_name, move |_: Params| {
		let url = match GLOBAL_PRIMITIVES_CACHE.get_untrusted_worker_url() {
			Ok(url) => url,
			Err(status) => {
				let error_msg: String = format!("Could not get untrusted url due to: {}", status);
				return Ok(json!(compute_hex_encoded_return_error(error_msg.as_str())))
			},
		};

		let json_value = RpcReturnValue::new(url.encode(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	// chain_subscribeAllHeads
	let chain_subscribe_all_heads_name: &str = "chain_subscribeAllHeads";
	io.add_sync_method(chain_subscribe_all_heads_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// state_getMetadata
	let state_get_metadata_name: &str = "state_getMetadata";
	io.add_sync_method(state_get_metadata_name, |_: Params| {
		let metadata = Runtime::metadata();
		let json_value = RpcReturnValue::new(metadata.into(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	// state_getRuntimeVersion
	let state_get_runtime_version_name: &str = "state_getRuntimeVersion";
	io.add_sync_method(state_get_runtime_version_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// state_get
	let state_get_name: &str = "state_get";
	io.add_sync_method(state_get_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_health
	let state_health_name: &str = "system_health";
	io.add_sync_method(state_health_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_name
	let state_name_name: &str = "system_name";
	io.add_sync_method(state_name_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// system_version
	let state_version_name: &str = "system_version";
	io.add_sync_method(state_version_name, |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	// returns all rpcs methods
	let rpc_methods_string = get_all_rpc_methods_string(&io);
	io.add_sync_method("rpc_methods", move |_: Params| {
		Ok(Value::String(rpc_methods_string.to_owned()))
	});

	io
}

pub fn sidechain_io_handler<ImportFn, Error>(import_fn: ImportFn) -> IoHandler
where
	ImportFn: Fn(SignedBlock) -> Result<(), Error> + Sync + Send + 'static,
	Error: std::fmt::Debug,
{
	let io = IoHandler::new();
	import_block_api::add_import_block_rpc_method(import_fn, io)
}

#[cfg(feature = "test")]
pub mod tests {
	use super::*;
	use std::string::ToString;

	pub fn test_given_io_handler_methods_then_retrieve_all_names_as_string() {
		let mut io = IoHandler::new();
		let method_names: [&str; 4] = ["method1", "another_method", "fancy_thing", "solve_all"];

		for method_name in method_names.iter() {
			io.add_sync_method(method_name, |_: Params| Ok(Value::String("".to_string())));
		}

		let method_string = get_all_rpc_methods_string(&io);

		for method_name in method_names.iter() {
			assert!(method_string.contains(method_name));
		}
	}
}
