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

extern {
	fn sgxwasm_init(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t ;
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SgxWasmAction {
	Call {
		module: Option<Vec<u8>>,
		function: String,
	},
}

#[derive(Debug, Serialize, Deserialize)]
pub enum BoundaryValue {
	I32(i32),
	I64(i64),
	F32(u32),
	F64(u64),
}

pub fn sgx_enclave_wasm_init(eid: sgx_enclave_id_t) -> Result<(),String> {
	let mut retval:sgx_status_t = sgx_status_t::SGX_SUCCESS;
	let result = unsafe {
		sgxwasm_init(eid, &mut retval)
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
