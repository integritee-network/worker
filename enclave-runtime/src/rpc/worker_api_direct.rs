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

use crate::{
	attestation::{
		generate_dcap_ra_extrinsic_from_quote_internal,
		generate_ias_ra_extrinsic_from_der_cert_internal,
	},
	utils::get_validator_accessor_from_solo_or_parachain,
};
use codec::Encode;
use core::result::Result;
use ita_sgx_runtime::Runtime;
use ita_stf::{Getter, TrustedCallSigned};
use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, ExtrinsicSender};
use itp_primitives_cache::{GetPrimitives, GLOBAL_PRIMITIVES_CACHE};
use itp_rpc::RpcReturnValue;
use itp_sgx_crypto::key_repository::AccessPubkey;
use itp_stf_executor::getter_executor::ExecuteGetter;
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{DirectRequestStatus, Request, ShardIdentifier, H256};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use its_primitives::types::block::SignedBlock;
use its_sidechain::rpc_handler::{direct_top_pool_api, import_block_api};
use jsonrpc_core::{serde_json::json, IoHandler, Params, Value};
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_runtime::OpaqueExtrinsic;
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

pub fn public_api_rpc_handler<Author, GetterExecutor, AccessShieldingKey>(
	top_pool_author: Arc<Author>,
	getter_executor: Arc<GetterExecutor>,
	shielding_key: Arc<AccessShieldingKey>,
) -> IoHandler
where
	Author: AuthorApi<H256, H256, TrustedCallSigned, Getter> + Send + Sync + 'static,
	GetterExecutor: ExecuteGetter + Send + Sync + 'static,
	AccessShieldingKey: AccessPubkey<KeyType = Rsa3072PubKey> + Send + Sync + 'static,
{
	let mut io =
		direct_top_pool_api::add_top_pool_direct_rpc_methods(top_pool_author, IoHandler::new());

	io.add_sync_method("author_getShieldingKey", move |_: Params| {
		let rsa_pubkey = match shielding_key.retrieve_pubkey() {
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

	io.add_sync_method("author_getMuRaUrl", move |_: Params| {
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

	io.add_sync_method("author_getUntrustedUrl", move |_: Params| {
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

	io.add_sync_method("chain_subscribeAllHeads", |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io.add_sync_method("state_getMetadata", |_: Params| {
		let metadata = Runtime::metadata();
		let json_value = RpcReturnValue::new(metadata.into(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	io.add_sync_method("state_getRuntimeVersion", |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io.add_sync_method("state_executeGetter", move |params: Params| {
		let json_value = match execute_getter_inner(getter_executor.as_ref(), params) {
			Ok(state_getter_value) => RpcReturnValue {
				do_watch: false,
				value: state_getter_value.encode(),
				status: DirectRequestStatus::Ok,
			}
			.to_hex(),
			Err(error) => compute_hex_encoded_return_error(error.as_str()),
		};
		Ok(json!(json_value))
	});

	io.add_sync_method("attesteer_forwardDcapQuote", move |params: Params| {
		let json_value = match forward_dcap_quote_inner(params) {
			Ok(val) => RpcReturnValue {
				do_watch: false,
				value: val.encode(),
				status: DirectRequestStatus::Ok,
			}
			.to_hex(),
			Err(error) => compute_hex_encoded_return_error(error.as_str()),
		};

		Ok(json!(json_value))
	});

	io.add_sync_method("attesteer_forwardIasAttestationReport", move |params: Params| {
		let json_value = match attesteer_forward_ias_attestation_report_inner(params) {
			Ok(val) => RpcReturnValue {
				do_watch: false,
				value: val.encode(),
				status: DirectRequestStatus::Ok,
			}
			.to_hex(),
			Err(error) => compute_hex_encoded_return_error(error.as_str()),
		};

		Ok(json!(json_value))
	});

	io.add_sync_method("system_health", |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io.add_sync_method("system_name", |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io.add_sync_method("system_version", |_: Params| {
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	let rpc_methods_string = get_all_rpc_methods_string(&io);
	io.add_sync_method("rpc_methods", move |_: Params| {
		Ok(Value::String(rpc_methods_string.to_owned()))
	});

	io
}

fn execute_getter_inner<GE: ExecuteGetter>(
	getter_executor: &GE,
	params: Params,
) -> Result<Option<Vec<u8>>, String> {
	let hex_encoded_params = params.parse::<Vec<String>>().map_err(|e| format!("{:?}", e))?;

	let request =
		Request::from_hex(&hex_encoded_params[0].clone()).map_err(|e| format!("{:?}", e))?;

	let shard: ShardIdentifier = request.shard;
	let encoded_trusted_getter: Vec<u8> = request.cyphertext;

	let getter_result = getter_executor
		.execute_getter(&shard, encoded_trusted_getter)
		.map_err(|e| format!("{:?}", e))?;

	Ok(getter_result)
}

fn forward_dcap_quote_inner(params: Params) -> Result<OpaqueExtrinsic, String> {
	let hex_encoded_params = params.parse::<Vec<String>>().map_err(|e| format!("{:?}", e))?;

	if hex_encoded_params.len() != 1 {
		return Err(format!(
			"Wrong number of arguments for IAS attestation report forwarding: {}, expected: {}",
			hex_encoded_params.len(),
			1
		))
	}

	let encoded_quote_to_forward: Vec<u8> =
		itp_utils::hex::decode_hex(&hex_encoded_params[0]).map_err(|e| format!("{:?}", e))?;

	let url = String::new();
	let ext = generate_dcap_ra_extrinsic_from_quote_internal(url, &encoded_quote_to_forward)
		.map_err(|e| format!("{:?}", e))?;

	let validator_access = get_validator_accessor_from_solo_or_parachain().unwrap();
	validator_access
		.execute_mut_on_validator(|v| v.send_extrinsics(vec![ext.clone()]))
		.unwrap();

	Ok(ext)
}

fn attesteer_forward_ias_attestation_report_inner(
	params: Params,
) -> Result<OpaqueExtrinsic, String> {
	let hex_encoded_params = params.parse::<Vec<String>>().map_err(|e| format!("{:?}", e))?;

	if hex_encoded_params.len() != 1 {
		return Err(format!(
			"Wrong number of arguments for IAS attestation report forwarding: {}, expected: {}",
			hex_encoded_params.len(),
			1
		))
	}

	let ias_attestation_report =
		itp_utils::hex::decode_hex(&hex_encoded_params[0]).map_err(|e| format!("{:?}", e))?;

	let url = String::new();
	let ext = generate_ias_ra_extrinsic_from_der_cert_internal(url, &ias_attestation_report)
		.map_err(|e| format!("{:?}", e))?;

	let validator_access = get_validator_accessor_from_solo_or_parachain().unwrap();
	validator_access
		.execute_mut_on_validator(|v| v.send_extrinsics(vec![ext.clone()]))
		.unwrap();

	Ok(ext)
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
