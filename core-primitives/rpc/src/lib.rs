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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(all(not(feature = "std"), feature = "sgx"))]
pub mod sgx_reexport_prelude {
	pub use serde_json_sgx as serde_json;
	pub use serde_sgx as serde;
}

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use serde_derive::{Deserialize, Serialize};

#[cfg(all(not(feature = "sgx"), feature = "std"))]
use serde::{Deserialize, Serialize};

use codec::{Decode, Encode};
use itp_types::DirectRequestStatus;
use std::{borrow::ToOwned, string::String, vec::Vec};

#[derive(Encode, Decode, Debug)]
pub struct RpcReturnValue {
	pub value: Vec<u8>,
	pub do_watch: bool,
	pub status: DirectRequestStatus,
	//pub signature: Signature,
}
impl RpcReturnValue {
	pub fn new(val: Vec<u8>, watch: bool, status: DirectRequestStatus) -> Self {
		Self {
			value: val,
			do_watch: watch,
			status,
			//signature: sign,
		}
	}

	pub fn from_error_message(error_msg: &str) -> Self {
		RpcReturnValue {
			value: error_msg.encode(),
			do_watch: false,
			status: DirectRequestStatus::Error,
		}
	}
}

#[derive(Clone, Encode, Decode, Debug, Serialize, Deserialize)]
pub struct RpcResponse {
	pub jsonrpc: String,
	pub result: String, // hex encoded RpcReturnValue
	pub id: u32,
}

#[derive(Clone, Encode, Decode, Serialize, Deserialize)]
pub struct RpcRequest {
	pub jsonrpc: String,
	pub method: String,
	pub params: Vec<String>,
	pub id: i32,
}

impl RpcRequest {
	pub fn compose_jsonrpc_call(
		method: String,
		params: Vec<String>,
	) -> Result<String, serde_json::Error> {
		serde_json::to_string(&RpcRequest { jsonrpc: "2.0".to_owned(), method, params, id: 1 })
	}
}
