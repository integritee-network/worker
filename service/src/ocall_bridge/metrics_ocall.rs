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

use crate::{
	ocall_bridge::bridge_api::{MetricsBridge, OCallBridgeError, OCallBridgeResult},
	prometheus_metrics::ReceiveEnclaveMetrics,
};
use codec::Decode;
use itp_enclave_metrics::EnclaveMetric;
use std::sync::Arc;

pub struct MetricsOCall<MetricsReceiver> {
	receiver: Arc<MetricsReceiver>,
}

impl<MetricsReceiver> MetricsOCall<MetricsReceiver> {
	pub fn new(receiver: Arc<MetricsReceiver>) -> Self {
		MetricsOCall { receiver }
	}
}

impl<MetricsReceiver> MetricsBridge for MetricsOCall<MetricsReceiver>
where
	MetricsReceiver: ReceiveEnclaveMetrics,
{
	fn update_metric(&self, metric_encoded: Vec<u8>) -> OCallBridgeResult<()> {
		let metric: EnclaveMetric =
			Decode::decode(&mut metric_encoded.as_slice()).map_err(|e| {
				OCallBridgeError::UpdateMetric(format!("Failed to decode metric: {:?}", e))
			})?;

		self.receiver.receive_enclave_metric(metric).map_err(|e| {
			OCallBridgeError::UpdateMetric(format!("Failed to receive enclave metric: {:?}", e))
		})
	}
}
