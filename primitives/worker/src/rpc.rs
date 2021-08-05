use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::string::String;

#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
// Todo: result should not be Vec<u8>, but `T: Serialize`
pub struct RpcResponse {
	pub jsonrpc: String,
	pub result: Vec<u8>, // encoded RpcReturnValue
	pub id: u32,
}

#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
// Todo: params should not be Vec<u8>, but `T: Serialize`
pub struct RpcRequest {
	pub jsonrpc: String,
	pub method: String,
	pub params: Vec<u8>,
	pub id: i32,
}

impl RpcRequest {
	pub fn compose_jsonrpc_call(method: String, data: Vec<u8>) -> String {
		let direct_invocation_call =
			RpcRequest { jsonrpc: "2.0".to_owned(), method, params: data, id: 1 };
		serde_json::to_string(&direct_invocation_call).unwrap()
	}
}
