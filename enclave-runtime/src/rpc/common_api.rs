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
	utils::{
		get_stf_enclave_signer_from_solo_or_parachain,
		get_validator_accessor_from_integritee_solo_or_parachain,
	},
};
use codec::Encode;
use core::result::Result;
use ita_sgx_runtime::Runtime;
use ita_stf::{Getter, TrustedCallSigned};
use itc_parentchain::light_client::{concurrent_access::ValidatorAccess, ExtrinsicSender};
use itp_primitives_cache::{GetPrimitives, GLOBAL_PRIMITIVES_CACHE};
use itp_rpc::RpcReturnValue;
use itp_sgx_crypto::key_repository::AccessPubkey;
use itp_stf_executor::{getter_executor::ExecuteGetter, traits::StfShardVaultQuery};
use itp_top_pool_author::traits::AuthorApi;
use itp_types::{DirectRequestStatus, Request, ShardIdentifier, H256};
use itp_utils::{FromHexPrefixed, ToHexPrefixed};
use jsonrpc_core::{serde_json::json, IoHandler, Params, Value};
use log::debug;
use sgx_crypto_helper::rsa3072::Rsa3072PubKey;
use sp_runtime::OpaqueExtrinsic;
use std::{format, str, string::String, sync::Arc, vec::Vec};

fn compute_hex_encoded_return_error(error_msg: &str) -> String {
	RpcReturnValue::from_error_message(error_msg).to_hex()
}

pub fn add_common_api<Author, GetterExecutor, AccessShieldingKey>(
	io_handler: &mut IoHandler,
	top_pool_author: Arc<Author>,
	getter_executor: Arc<GetterExecutor>,
	shielding_key: Arc<AccessShieldingKey>,
) where
	Author: AuthorApi<H256, H256, TrustedCallSigned, Getter> + Send + Sync + 'static,
	GetterExecutor: ExecuteGetter + Send + Sync + 'static,
	AccessShieldingKey: AccessPubkey<KeyType = Rsa3072PubKey> + Send + Sync + 'static,
{
	io_handler.add_sync_method("author_getShieldingKey", move |_: Params| {
		debug!("worker_api_direct rpc was called: author_getShieldingKey");
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

	let local_top_pool_author = top_pool_author.clone();
	io_handler.add_sync_method("author_getShardVault", move |_: Params| {
		debug!("worker_api_direct rpc was called: author_getShardVault");
		let shard =
			local_top_pool_author.list_handled_shards().first().copied().unwrap_or_default();
		if let Ok(stf_enclave_signer) = get_stf_enclave_signer_from_solo_or_parachain() {
			if let Ok(vault) = stf_enclave_signer.get_shard_vault(&shard) {
				let json_value =
					RpcReturnValue::new(vault.encode(), false, DirectRequestStatus::Ok);
				Ok(json!(json_value.to_hex()))
			} else {
				Ok(json!(compute_hex_encoded_return_error("failed to get shard vault").to_hex()))
			}
		} else {
			Ok(json!(compute_hex_encoded_return_error(
				"failed to get stf_enclave_signer to get shard vault"
			)
			.to_hex()))
		}
	});

	io_handler.add_sync_method("author_getShard", move |_: Params| {
		debug!("worker_api_direct rpc was called: author_getShard");
		let shard = top_pool_author.list_handled_shards().first().copied().unwrap_or_default();
		let json_value = RpcReturnValue::new(shard.encode(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	io_handler.add_sync_method("author_getMuRaUrl", move |_: Params| {
		debug!("worker_api_direct rpc was called: author_getMuRaUrl");
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

	io_handler.add_sync_method("author_getUntrustedUrl", move |_: Params| {
		debug!("worker_api_direct rpc was called: author_getUntrustedUrl");
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

	io_handler.add_sync_method("chain_subscribeAllHeads", |_: Params| {
		debug!("worker_api_direct rpc was called: chain_subscribeAllHeads");
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io_handler.add_sync_method("state_getMetadata", |_: Params| {
		debug!("worker_api_direct rpc was called: tate_getMetadata");
		let metadata = Runtime::metadata();
		let json_value = RpcReturnValue::new(metadata.into(), false, DirectRequestStatus::Ok);
		Ok(json!(json_value.to_hex()))
	});

	io_handler.add_sync_method("state_getRuntimeVersion", |_: Params| {
		debug!("worker_api_direct rpc was called: state_getRuntimeVersion");
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io_handler.add_sync_method("state_executeGetter", move |params: Params| {
		debug!("worker_api_direct rpc was called: state_executeGetter");
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

	io_handler.add_sync_method("attesteer_forwardDcapQuote", move |params: Params| {
		debug!("worker_api_direct rpc was called: attesteer_forwardDcapQuote");
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

	io_handler.add_sync_method("attesteer_forwardIasAttestationReport", move |params: Params| {
		debug!("worker_api_direct rpc was called: attesteer_forwardIasAttestationReport");
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

	io_handler.add_sync_method("system_health", |_: Params| {
		debug!("worker_api_direct rpc was called: system_health");
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io_handler.add_sync_method("system_name", |_: Params| {
		debug!("worker_api_direct rpc was called: system_name");
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});

	io_handler.add_sync_method("system_version", |_: Params| {
		debug!("worker_api_direct rpc was called: system_version");
		let parsed = "world";
		Ok(Value::String(format!("hello, {}", parsed)))
	});
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

	let validator_access = get_validator_accessor_from_integritee_solo_or_parachain().unwrap();
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

	let validator_access = get_validator_accessor_from_integritee_solo_or_parachain().unwrap();
	validator_access
		.execute_mut_on_validator(|v| v.send_extrinsics(vec![ext.clone()]))
		.unwrap();

	Ok(ext)
}
