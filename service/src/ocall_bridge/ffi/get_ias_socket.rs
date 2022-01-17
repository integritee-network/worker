/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use crate::ocall_bridge::bridge_api::{Bridge, RemoteAttestationBridge};
use log::*;
use sgx_types::{c_int, sgx_status_t};
use std::sync::Arc;

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
	get_ias_socket(ret_fd, Bridge::get_ra_api()) // inject the RA API (global state)
}

fn get_ias_socket(ret_fd: *mut c_int, ra_api: Arc<dyn RemoteAttestationBridge>) -> sgx_status_t {
	debug!("    Entering ocall_get_ias_socket");
	let socket_result = ra_api.get_ias_socket();

	return match socket_result {
		Ok(s) => {
			unsafe {
				*ret_fd = s;
			}
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => {
			error!("[-]  Failed to get IAS socket: {:?}", e);
			return e.into()
		},
	}
}

#[cfg(test)]
mod tests {

	use super::*;
	use crate::ocall_bridge::bridge_api::{MockRemoteAttestationBridge, OCallBridgeError};
	use std::sync::Arc;

	#[test]
	fn get_socket_sets_pointer_result() {
		let expected_socket = 4321i32;

		let mut ra_ocall_api_mock = MockRemoteAttestationBridge::new();
		ra_ocall_api_mock
			.expect_get_ias_socket()
			.times(1)
			.returning(move || Ok(expected_socket));

		let mut ias_sock: i32 = 0;

		let ret_status = get_ias_socket(&mut ias_sock as *mut i32, Arc::new(ra_ocall_api_mock));

		assert_eq!(ret_status, sgx_status_t::SGX_SUCCESS);
		assert_eq!(ias_sock, expected_socket);
	}

	#[test]
	fn given_error_from_ocall_impl_then_return_sgx_error() {
		let mut ra_ocall_api_mock = MockRemoteAttestationBridge::new();
		ra_ocall_api_mock
			.expect_get_ias_socket()
			.times(1)
			.returning(|| Err(OCallBridgeError::GetIasSocket("test error".to_string())));

		let mut ias_sock: i32 = 0;
		let ret_status = get_ias_socket(&mut ias_sock as *mut i32, Arc::new(ra_ocall_api_mock));

		assert_ne!(ret_status, sgx_status_t::SGX_SUCCESS);
		assert_eq!(ias_sock, 0);
	}
}
