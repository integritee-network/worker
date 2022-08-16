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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use codec::Encode;
use itp_ocall_api::EnclaveMetricsOCallApi;
use sgx_types::SgxResult;
use std::vec::Vec;

/// Metrics o-call mock.
#[derive(Default)]
pub struct MetricsOCallMock {
	metric_updates: RwLock<Vec<Vec<u8>>>,
}

impl Clone for MetricsOCallMock {
	fn clone(&self) -> Self {
		MetricsOCallMock {
			metric_updates: RwLock::new(self.metric_updates.read().unwrap().clone()),
		}
	}
}

impl MetricsOCallMock {
	pub fn get_metrics_updates(&self) -> Vec<Vec<u8>> {
		self.metric_updates.read().unwrap().clone()
	}
}

impl EnclaveMetricsOCallApi for MetricsOCallMock {
	fn update_metric<Metric: Encode>(&self, metric: Metric) -> SgxResult<()> {
		self.metric_updates.write().unwrap().push(metric.encode());
		Ok(())
	}
}
