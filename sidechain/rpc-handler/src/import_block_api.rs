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
use its_primitives::types::SignedBlock;
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
	let sidechain_import_import_name: &str = "sidechain_importBlock";
	io_handler.add_sync_method(sidechain_import_import_name, move |sidechain_blocks: Params| {
		debug!("sidechain_importBlock rpc. Params: {:?}", sidechain_blocks);

		let block_vec: Vec<u8> = sidechain_blocks.parse()?;

		let blocks: Vec<SignedBlock> = Decode::decode(&mut block_vec.as_slice()).map_err(|_| {
			jsonrpc_core::error::Error::invalid_params_with_details(
				"Could not decode Vec<SignedBlock>",
				block_vec,
			)
		})?;

		info!("sidechain_importBlock. Blocks: {:?}", blocks);

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
		let enclave_req = r#"{"jsonrpc":"2.0","method":"sidechain_importBlock","params":[4,0,0,0,0,0,0,0,0,228,0,145,188,97,251,138,131,108,29,6,107,10,152,67,29,148,190,114,167,223,169,197,163,93,228,76,169,171,80,15,209,101,11,211,96,0,0,0,0,83,52,167,255,37,229,185,231,38,66,122,3,55,139,5,190,125,85,94,177,190,99,22,149,92,97,154,30,142,89,24,144,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,136,220,52,23,213,5,142,196,180,80,62,12,18,234,26,10,137,190,32,15,233,137,34,66,61,67,52,1,79,166,176,238,0,0,0,175,124,84,84,32,238,162,224,130,203,26,66,7,121,44,59,196,200,100,31,173,226,165,106,187,135,223,149,30,46,191,95,116,203,205,102,100,85,82,74,158,197,166,218,181,130,119,127,162,134,227,129,118,85,123,76,21,113,90,1,160,77,110,15],"id":1}"#;

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
