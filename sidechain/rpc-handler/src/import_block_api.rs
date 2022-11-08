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

use crate::constants::RPC_METHOD_NAME_IMPORT_BLOCKS;
use itp_utils::FromHexPrefixed;
use its_primitives::types::SignedBlock;
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

		debug!("{}. Blocks: {:?}", RPC_METHOD_NAME_IMPORT_BLOCKS, blocks);

		for block in blocks {
			info!("Add block {} to import queue", block.block.header.block_number);
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
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":["0x04a7417cf9370af5ea5cf64f107aa49ebf320dbf10c6d0ef200ef7c5d57c9f4b956d000000000000007dba6b8e1f8f38f7f517dbd4a3eaeb27a97958d7a1d1541f69db5d24b3c48cd0dc376b08fcb44dca19a08a0445023a5f4bef80019b518296313e83fc105c669064000000000000005f08a5f98301000081bd02d7e1f8b6ab9a64fa8fdaa379fc1c9208bf0d341689c2342ce8a314e174768f40dfe0fadf2e7347f2ec83a541427a0931ce54ce7a4506184198c2e7aed3006d031b2cc662bbcd54ca1cc09f0021d956673c4905b07edf0b9f323d2078fc4d8cbaefe34353bc731f9a1ef14dfd6b58274a6efbbc6c2c4261d304b979305f501819df33452f2f276add2f3650b825c700abf23790a6787baf1cabb208633eb33fb66e987a99193fbd2c07374502dc0fdff6d7a5d462b2a9c0196711437aa6a30ce52ae6e4818a643df256c026b08d7ccca2de46f368630512073b271397719f34c9b8612c7f1707d06b45206da268f49b5b5159b3418093512700ecb67ccbc5bd9a1731a9c67372b39ec3761d12afb445a6c8580b97a090f4bb06ff70001bc44f7f91ada7f92f0064188d08c16594ddb4fd09f65bee5f4b3c92b80091d3fe5bc89f3fb95a96941563126a6379b806981dd7f225c7e3ac4e1ee0509de406"],"id":1}"#;

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
