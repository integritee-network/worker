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

use crate::{command_utils::get_worker_api_direct, Cli};
use itc_rpc_client::direct_client::DirectApi;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_types::DirectRequestStatus;
use itp_utils::FromHexPrefixed;
use log::*;
use std::fs::read_to_string;

/// Forward DCAP quote for verification.
#[derive(Debug, Clone, Parser)]
pub struct SendDcapQuoteCmd {
	/// Hex encoded DCAP quote filename.
	quote: String,
}

impl SendDcapQuoteCmd {
	pub fn run(&self, cli: &Cli) {
		let direct_api = get_worker_api_direct(cli);
		let hex_encoded_quote = read_to_string(&self.quote)
			.map_err(|e| error!("Opening hex encoded DCAP quote file failed: {:#?}", e))
			.unwrap();

		let rpc_method = "attesteer_callForwardDCAPQuote".to_owned();
		let jsonrpc_call: String =
			RpcRequest::compose_jsonrpc_call(rpc_method, vec![hex_encoded_quote]).unwrap();

		let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();

		// Decode RPC response.
		let rpc_response: RpcResponse = serde_json::from_str(&rpc_response_str).ok().unwrap();
		let rpc_return_value = RpcReturnValue::from_hex(&rpc_response.result)
			// Replace with `inspect_err` once it's stable.
			.map_err(|e| {
				error!("Failed to decode RpcReturnValue: {:?}", e);
				e
			})
			.ok()
			.unwrap();

		match rpc_return_value.status {
			DirectRequestStatus::Ok => println!("DCAP quote verification succeded."),
			_ => error!("DCAP quote verification failed"),
		}
	}
}
