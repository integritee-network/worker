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

use sgx_types::*;
use sgx_urts::SgxEnclave;

// use std::io::{Read, Write};
// use std::{fs, path};

use wasm_def::{RuntimeValue, Error as InterpreterError};

// static ENCLAVE_FILE: &'static str = "./bin/enclave.signed.so";
// static ENCLAVE_TOKEN: &'static str = "./bin/enclave.token";

extern {
	fn sgxwasm_init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t ;
	fn sgxwasm_run_action(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
						  req_bin : *const u8, req_len: usize,
						  result_bin : *mut u8,
						  result_max_len : usize ) -> sgx_status_t;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SgxWasmAction {
	Invoke {
		module: Option<Vec<u8>>,
		field: String,
		args: Vec<BoundaryValue>
	},
	Get {
		module: Option<String>,
		field: String,
	},
	LoadModule {
		name: Option<String>,
		module: Vec<u8>,
	},
	TryLoad {
		module: Vec<u8>,
	},
	Register {
		name: Option<String>,
		as_name: String,
	},
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BoundaryValue {
	I32(i32),
	I64(i64),
	F32(u32),
	F64(u64),
}

fn boundary_value_to_runtime_value(rv: BoundaryValue) -> RuntimeValue {
	match rv {
		BoundaryValue::I32(bv) => RuntimeValue::I32(bv),
		BoundaryValue::I64(bv) => RuntimeValue::I64(bv),
		BoundaryValue::F32(bv) => RuntimeValue::F32(bv.into()),
		BoundaryValue::F64(bv) => RuntimeValue::F64(bv.into()),
	}
}

pub fn answer_convert(res : Result<Option<BoundaryValue>, InterpreterError>)
					 ->  Result<Option<RuntimeValue>, InterpreterError>
{
	match res {
		Ok(None) => Ok(None),
		Ok(Some(rv)) => Ok(Some(boundary_value_to_runtime_value(rv))),
		Err(x) => Err(x),
	}
}

pub fn sgx_enclave_wasm_init(enclave : &SgxEnclave) -> Result<(),String> {
	let mut retval:sgx_status_t = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		sgxwasm_init(enclave.geteid(),
					 &mut retval)
	};

	match result {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", result.as_str());
			panic!("sgx_enclave_wasm_init's ECALL returned unknown error!");
		}
	}

	match retval {
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Function return fail: {}!", retval.as_str());
			return Err(format!("ECALL func return error: {}", retval.as_str()));
		}
	}

	Ok(())
}

pub fn sgx_enclave_wasm_invoke(req_str : String,
						   result_max_len : usize,
						   enclave : &SgxEnclave) -> (Result<Option<BoundaryValue>, InterpreterError>, sgx_status_t) {
	let enclave_id = enclave.geteid();
	let mut ret_val = sgx_status_t::SGX_SUCCESS;
	let     req_bin = req_str.as_ptr() as * const u8;
	let     req_len = req_str.len();

	let mut result_vec:Vec<u8> = vec![0; result_max_len];
	let     result_slice = &mut result_vec[..];

	let sgx_ret = unsafe{sgxwasm_run_action(enclave_id,
									 &mut ret_val,
									 req_bin,
									 req_len,
									 result_slice.as_mut_ptr(),
									 result_max_len)};

	match sgx_ret {
		// sgx_ret falls in range of Intel's Error code set
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			println!("[-] ECALL Enclave Failed {}!", sgx_ret.as_str());
			panic!("sgx_enclave_wasm_load_invoke's ECALL returned unknown error!");
		}
	}

	// We need to trim all trailing '\0's before conver to string
	let mut result_vec:Vec<u8> = result_slice.to_vec();
	result_vec.retain(|x| *x != 0x00u8);

	let result:Result<Option<BoundaryValue>, InterpreterError>;
	// Now result_vec only includes essential chars
	if result_vec.len() == 0 {
		result = Ok(None);
	}
	else{
		let raw_result_str = String::from_utf8(result_vec).unwrap();
		result = serde_json::from_str(&raw_result_str).unwrap();
	}

	match ret_val {
		// ret_val falls in range of [SGX_SUCCESS + SGX_ERROR_WASM_*]
		sgx_status_t::SGX_SUCCESS => {},
		_ => {
			// In this case, the returned buffer is useful
			return (result, ret_val);
		}
	}

	// ret_val should be SGX_SUCCESS here
	(result, ret_val)
}
