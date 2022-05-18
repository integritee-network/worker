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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use itp_utils::FromHexPrefixed;
use its_primitives::{constants::RPC_METHOD_NAME_IMPORT_BLOCKS, types::SignedBlock};
use jsonrpc_core::{IoHandler, Params, Value};
use log::*;
use std::{borrow::ToOwned, fmt::Debug, string::String, vec::Vec};

pub fn add_import_block_rpc_method<ImportFn, Error>(
	import_fn: ImportFn,
	mut io_handler: IoHandler,
) -> IoHandler
where
	ImportFn: Fn(SignedBlock) -> Result<(), Error> + Sync + Send + 'static,
	Error: Debug,
{
	let sidechain_import_import_name: &str = RPC_METHOD_NAME_IMPORT_BLOCKS;
	io_handler.add_sync_method(sidechain_import_import_name, move |sidechain_blocks: Params| {
		debug!("{} rpc. Params: {:?}", RPC_METHOD_NAME_IMPORT_BLOCKS, sidechain_blocks);

		let hex_encoded_block_vec: Vec<String> = sidechain_blocks.parse()?;

		let blocks = Vec::<SignedBlock>::from_hex(&hex_encoded_block_vec[0]).map_err(|_| {
			jsonrpc_core::error::Error::invalid_params_with_details(
				"Could not decode Vec<SignedBlock>",
				hex_encoded_block_vec,
			)
		})?;

		info!("{}. Blocks: {:?}", RPC_METHOD_NAME_IMPORT_BLOCKS, blocks);

		for block in blocks {
			let _ = import_fn(block).map_err(|e| {
				let error = jsonrpc_core::error::Error::invalid_params_with_details(
					"Failed to import Block.",
					e,
				);
				error!("{:?}", error);
			});
		}

		Ok(Value::String("ok".to_owned()))
	});

	io_handler
}

#[cfg(test)]
pub mod tests {

	use super::*;

	fn rpc_response<T: ToString>(result: T) -> String {
		format!(r#"{{"jsonrpc":"2.0","result":{},"id":1}}"#, result.to_string())
	}

	fn io_handler() -> IoHandler {
		let io_handler = IoHandler::new();
		add_import_block_rpc_method::<_, String>(|_| Ok(()), io_handler)
	}

	#[test]
	pub fn sidechain_import_block_is_ok() {
		let io = io_handler();
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":["0x042aa533a21d26d94c29094a626ed08322d1f73fe95ff7b5d1edd129011441b5681a0000000000000096dbbe8c2ba45178c554d134096990f9f5dba477b008cbef4f1934a0bac306f84b9981cab5445b00773dc92d873850c6ee3bc48153af062aec2d1e1f549e5f801f72f2d180010000bc3070e3cc5beed3103c6d50b83dcb8888dc14d6baa4dc2f97543a61893a743329a5a289c17a355063e21136c9ebcad7d2228dcb2a2495a34e6e97ff1338f644005d023a6a5049e17c7358bc02cb474d65eb6f158b901009c2066ba8cc69c4da3e0195ee6ae9f3c7e38e7ed39830ade0015190a356173d275ffb18d229649e140b9f530a2ad74d70e3984267a78b568196c7433c9d1a88d0d18ea96d83c3b04c56e97af3d1eb1b7d134f79938218514ec2f9b485712a56d8d48f415dc952063fa0677dd7c1d5fda17d2883b363911da13dee66754693ff0ab8da0017a3670a93afdb90bf486bb884c134bb7503b9df4821738ce1e379d8f3b98fb03e48475581856b452a1eab1ea7a098473a74b9e08056523f8f2b522af65bc908"],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		assert_eq!(response_string, rpc_response("\"ok\""));
	}

	#[test]
	pub fn sidechain_import_block_returns_invalid_param_err() {
		let io = io_handler();
		let enclave_req =
			r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[4,214,133,100],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params: invalid type: integer `4`, expected a string."},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}

	#[test]
	pub fn sidechain_import_block_returns_decode_err() {
		let io = io_handler();
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":["SophisticatedInvalidParam"],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: Could not decode Vec<SignedBlock>","data":"[\"SophisticatedInvalidParam\"]"},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}

	pub fn sidechain_import_block_returns_decode_err_for_valid_hex() {
		let io = io_handler();

		let enclave_req =
			r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params": ["0x11"],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: Could not decode Vec<SignedBlock>","data":"[17]"},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}
}
