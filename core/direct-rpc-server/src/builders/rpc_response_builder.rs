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

use crate::builders::rpc_return_value_builder::RpcReturnValueBuilder;
use itp_rpc::{RpcResponse, RpcReturnValue};
use itp_utils::ToHexPrefixed;

/// builder pattern for RpcResponse
pub struct RpcResponseBuilder {
	maybe_id: Option<u32>,
	maybe_json_rpc: Option<String>,
	maybe_result: Option<RpcReturnValue>,
}

impl RpcResponseBuilder {
	#[allow(unused)]
	pub fn new() -> Self {
		RpcResponseBuilder { maybe_id: None, maybe_json_rpc: None, maybe_result: None }
	}

	#[allow(unused)]
	pub fn with_id(mut self, id: u32) -> Self {
		self.maybe_id = Some(id);
		self
	}

	#[allow(unused)]
	pub fn with_json_rpc(mut self, json_rpc: String) -> Self {
		self.maybe_json_rpc = Some(json_rpc);
		self
	}

	#[allow(unused)]
	pub fn with_result(mut self, result: RpcReturnValue) -> Self {
		self.maybe_result = Some(result);
		self
	}

	#[allow(unused)]
	pub fn build(self) -> RpcResponse {
		let id = self.maybe_id.unwrap_or(1u32);
		let json_rpc = self.maybe_json_rpc.unwrap_or(String::from("json_rpc"));
		let result = self
			.maybe_result
			.unwrap_or_else(|| RpcReturnValueBuilder::new().build())
			.to_hex();

		RpcResponse { result, jsonrpc: json_rpc, id }
	}
}
