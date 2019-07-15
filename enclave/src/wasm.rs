/*
	Copyright 2019 Supercomputing Systems AG

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

#![cfg_attr(target_env = "sgx", feature(rustc_private))]

use sgx_status_t;
use sgx_types::*;
use wasmi::{ImportsBuilder, Module, ModuleInstance, NopExternals, RuntimeValue};

use AllCounts;
use Message;
use sgxwasm::SpecDriver;
use std::string::ToString;
use std::sync::SgxMutex;
use log::*;

// lazy_static!{
	// static ref SPECDRIVER: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
// }

#[no_mangle]
pub extern "C"
fn sgxwasm_init() -> sgx_status_t {
	let spec_driver: SgxMutex<SpecDriver> = SgxMutex::new(SpecDriver::new());
	let mut sd = spec_driver.lock().unwrap();
	*sd = SpecDriver::new();
	sgx_status_t::SGX_SUCCESS
}


pub fn compare_hashes(act: sgx_sha256_hash_t, client: sgx_sha256_hash_t) -> Result<sgx_status_t, sgx_status_t> {
	// compare the hashes and return error if not matching
	if act == client {
		info!("    [Enclave] SHA256 of WASM code identical");
		Ok(sgx_status_t::SGX_SUCCESS)
	} else {
		warn!("    [Enclave] SHA256 of WASM code not matching");
		warn!("    [Enclave]   Wanted by client    : {:?}", client);
		warn!("    [Enclave]   Calculated by worker: {:?}", act);
		warn!("    [Enclave] Returning ERROR_UNEXPECTED and not updating oSTF");
		Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}
}

pub fn invoke_wasm_action(action: sgxwasm::SgxWasmAction, msg: Message, counter: &mut AllCounts) -> Result<sgx_status_t, sgx_status_t> {
	match action {
		sgxwasm::SgxWasmAction::Call { module, function } => {
			let _module = Module::from_buffer(module.unwrap()).unwrap();
			let instance =
				ModuleInstance::new(
					&_module,
					&ImportsBuilder::default()
				)
					.expect("failed to instantiate wasm module")
					.assert_no_start();

			let args = vec![RuntimeValue::I32(*counter.entries.entry(msg.account.to_string()).or_insert(0) as i32),
							RuntimeValue::I32(msg.amount as i32)
			];
			debug!("    [Enclave] Calling WASM with arguments = {:?}", args);

			let r = instance.invoke_export(&function, &args, &mut NopExternals);
			debug!("    [Enclave] invoke_export successful. r = {:?}", r);

			match r {
				Ok(Some(RuntimeValue::I32(v))) => {
					info!("    [Enclave] Counter Value of {}: '{}'", msg.account, v);
					counter.entries.insert(msg.account.to_string(), v as u32);
					info!("    [Enclave] WASM executed and counter updated");
					Ok(sgx_status_t::SGX_SUCCESS)
				},
				_ => {
					error!("    [Enclave] Could not decode result");
					Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
				}
			}
		},
		_ => {
			error!("    [Enclave] Unsupported action");
			Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
		},
	}
}
