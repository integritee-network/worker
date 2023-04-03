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
use log::*;
use std::fs::read_to_string;

use crate::{command_utils::get_worker_api_direct, Cli};

/// Forward IAS attestation report for verification.
#[derive(Debug, Clone, Parser)]
pub struct SendIasAttestationReportCmd {
	/// Hex encoded IAS attestation report filename.
	report: String,
}

impl SendIasAttestationReportCmd {
	pub fn run(&self, cli: &Cli) {
		let direct_api = get_worker_api_direct(cli);
		let hex_encoded_report = match read_to_string(&self.report) {
			Ok(hex_encoded_report) => hex_encoded_report,
			Err(e) => panic!("Opening hex encoded IAS attestation report file failed: {:#?}", e),
		};

		//let request = Request { shard, cyphertext: hex_encoded_quote.to_vec() };

		let rpc_method = "attesteer_forwardIasAttestationReport".to_owned();
		let jsonrpc_call: String =
			RpcRequest::compose_jsonrpc_call(rpc_method, vec![hex_encoded_report]).unwrap();

		let rpc_response_str = direct_api.get(&jsonrpc_call).unwrap();

		// Decode RPC response.
		let Ok(rpc_response) = serde_json::from_str::<RpcResponse>(&rpc_response_str) else {
			panic!("Can't parse RPC response: '{rpc_response_str}'");
		};
		let rpc_return_value = match RpcReturnValue::from_hex(&rpc_response.result) {
			Ok(rpc_return_value) => rpc_return_value,
			Err(e) => panic!("Failed to decode RpcReturnValue: {:?}", e),
		};

		match rpc_return_value.status {
			DirectRequestStatus::Ok => println!("IAS attestation report verification succeded."),
			_ => error!("IAS attestation report verification failed"),
		}
	}
}
