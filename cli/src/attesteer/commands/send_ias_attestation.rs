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

use itc_rpc_client::direct_client::DirectApi;
use itp_rpc::{RpcRequest, RpcResponse, RpcReturnValue};
use itp_types::DirectRequestStatus;
use itp_utils::FromHexPrefixed;
use log::error;
use std::fs::read_to_string;

use crate::{command_utils::get_worker_api_direct, Cli};

/// Forward IAS attestation report for verification.
#[derive(Debug, Clone, Parser)]
pub struct SendIASAttestationReportCmd {
	/// Hex encoded IAS attestation report filename.
	report: String,
}

impl SendIASAttestationReportCmd {
	pub fn run(&self, cli: &Cli) {
		let direct_api = get_worker_api_direct(&cli);
		let hex_encoded_report = read_to_string(&self.report)
			.map_err(|e| error!("Opening hex encoded IAS attestation report file failed: {:#?}", e))
			.unwrap();

		//let request = Request { shard, cyphertext: hex_encoded_quote.to_vec() };

		let rpc_method = "attesteer_forward_ias_attestation_report".to_owned();
		let jsonrpc_call: String =
			RpcRequest::compose_jsonrpc_call(rpc_method, vec![hex_encoded_report]).unwrap();

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
			DirectRequestStatus::Ok => println!("IAS attestation report verification succeded."),
			_ => error!("IAS attestation report verification failed"),
		}
	}
}
