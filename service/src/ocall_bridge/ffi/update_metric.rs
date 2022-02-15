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

use crate::ocall_bridge::bridge_api::{Bridge, MetricsBridge};
use log::*;
use sgx_types::sgx_status_t;
use std::{slice, sync::Arc};

/// # Safety
///
/// FFI are always unsafe
#[no_mangle]
pub unsafe extern "C" fn ocall_update_metric(
	metric_ptr: *const u8,
	metric_size: u32,
) -> sgx_status_t {
	update_metric(metric_ptr, metric_size, Bridge::get_metrics_api())
}

fn update_metric(
	metric_ptr: *const u8,
	metric_size: u32,
	oc_api: Arc<dyn MetricsBridge>,
) -> sgx_status_t {
	let metric_encoded: Vec<u8> =
		unsafe { Vec::from(slice::from_raw_parts(metric_ptr, metric_size as usize)) };

	match oc_api.update_metric(metric_encoded) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => {
			error!("update_metric o-call failed: {:?}", e);
			sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	}
}
