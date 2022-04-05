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

use codec::Decode;
use its_primitives::{constants::RPC_METHOD_NAME_IMPORT_BLOCKS, types::SignedBlock};
use jsonrpc_core::{IoHandler, Params, Value};
use log::*;
use std::{borrow::ToOwned, fmt::Debug, vec::Vec};

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

		let block_vec: Vec<u8> = sidechain_blocks.parse()?;

		let blocks: Vec<SignedBlock> = Decode::decode(&mut block_vec.as_slice()).map_err(|_| {
			jsonrpc_core::error::Error::invalid_params_with_details(
				"Could not decode Vec<SignedBlock>",
				block_vec,
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
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[4,214,133,100,93,246,175,226,132,221,148,110,92,136,126,102,210,76,31,161,70,134,211,78,164,161,10,161,244,238,152,16,78,27,0,0,0,0,0,0,0,73,116,2,132,31,80,15,47,213,32,2,41,26,189,99,86,235,175,172,213,177,240,105,72,195,176,9,208,70,199,175,14,111,195,7,63,174,8,7,34,199,161,58,166,190,254,107,27,93,9,249,239,10,56,116,174,164,10,185,247,206,95,80,15,200,62,48,254,127,1,0,0,34,46,253,86,156,211,88,25,46,128,216,4,146,5,112,16,125,206,126,34,116,34,61,177,72,2,249,236,225,168,199,27,6,165,15,16,239,22,74,141,152,34,57,191,166,40,181,130,194,202,238,12,244,63,191,131,115,91,89,117,94,49,0,245,0,93,2,38,58,201,204,121,130,251,179,198,127,37,203,37,1,198,62,200,247,175,68,5,83,206,13,146,229,140,187,255,177,22,84,184,68,7,65,168,141,97,207,86,192,169,203,166,205,126,227,238,1,142,81,214,23,245,197,242,73,40,30,103,235,174,202,80,142,248,57,25,98,190,36,106,6,177,153,229,124,145,253,136,80,0,132,19,152,227,134,116,244,125,45,200,160,89,219,24,68,47,239,41,164,159,103,60,111,21,180,251,193,8,188,180,207,212,10,244,187,140,49,161,46,103,199,71,191,207,167,59,98,108,149,234,93,222,228,176,249,126,130,54,226,112,233,235,92,214,100,228,91,55,0,196,187,51,131,66,61,113,185,228,191,189,214,210,69,169,201,223,67,81,250,108,128,172,119,239,90,189,173,189,174,140,196,44,236,75,84,83,37,148,210,128,196,228,214,165,43,92,135,31,170,200,130,176,253,255,62,23,164,183,122,98,163,28,7],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		assert_eq!(response_string, rpc_response("\"ok\""));
	}

	#[test]
	pub fn sidechain_import_block_returns_invalid_param_err() {
		let io = io_handler();
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":["SophisticatedInvalidParam"],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params: invalid type: string \"SophisticatedInvalidParam\", expected u8."},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}

	#[test]
	pub fn sidechain_import_block_returns_decode_err() {
		let io = io_handler();
		let enclave_req =
			r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[2],"id":1}"#;

		let response_string = io.handle_request_sync(enclave_req).unwrap();

		let err_msg = r#"{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid parameters: Could not decode Vec<SignedBlock>","data":"[2]"},"id":1}"#;
		assert_eq!(response_string, err_msg);
	}
}
