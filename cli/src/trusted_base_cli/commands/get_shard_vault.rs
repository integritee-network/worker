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
	command_utils::get_worker_api_direct,
	get_layer_two_nonce,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_operation::perform_trusted_operation,
	Cli, CliError, CliResult, CliResultOk,
};
use base58::ToBase58;
use codec::{Decode, Encode};
use ita_stf::{Getter, Index, TrustedCall, TrustedCallSigned};
use itc_rpc_client::direct_client::DirectApi;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use itp_types::{AccountId, DirectRequestStatus};
use itp_utils::FromHexPrefixed;
use log::*;
use my_node_runtime::Balance;
use sp_core::{crypto::Ss58Codec, Pair, H256};
use std::boxed::Box;

#[derive(Parser)]
pub struct GetShardVaultCommand {}

impl GetShardVaultCommand {
	pub(crate) fn run(&self, cli: &Cli, _trusted_args: &TrustedCli) -> CliResult {
		let direct_api = get_worker_api_direct(cli);
		let rpc_method = "author_getShardVault".to_owned();
		let jsonrpc_call: String = RpcRequest::compose_jsonrpc_call(rpc_method, vec![]).unwrap();
		let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();
		// Decode RPC response.
		let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str)
			.map_err(|err| CliError::WorkerRpcApi { msg: err.to_string() })?;
		let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
			// Replace with `inspect_err` once it's stable.
			.map_err(|err| {
				error!("Failed to decode RpcReturnValue: {:?}", err);
				CliError::WorkerRpcApi { msg: "failed to decode RpcReturnValue".to_string() }
			})?;

		if rpc_return_value.status == DirectRequestStatus::Error {
			println!("[Error] {}", String::decode(&mut rpc_return_value.value.as_slice()).unwrap());
			return Err(CliError::WorkerRpcApi { msg: "rpc error".to_string() })
		}

		let vault = AccountId::decode(&mut rpc_return_value.value.as_slice())
			// Replace with `inspect_err` once it's stable.
			.map_err(|err| {
				error!("Failed to decode vault account: {:?}", err);
				CliError::WorkerRpcApi { msg: err.to_string() }
			})?;
		let vault_ss58 = vault.to_ss58check();
		println!("{}", vault_ss58);
		Ok(CliResultOk::PubKeysBase58 {
			pubkeys_sr25519: None,
			pubkeys_ed25519: Some(vec![vault_ss58]),
		})
	}
}
