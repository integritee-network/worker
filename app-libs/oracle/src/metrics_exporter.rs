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

use crate::types::{ExchangeRate, TradingPair};
use itp_enclave_metrics::{EnclaveMetric, ExchangeRateOracleMetric, OracleMetric};
use itp_ocall_api::EnclaveMetricsOCallApi;
use log::error;
use std::{string::String, sync::Arc, time::Instant};

/// Trait to export metrics for any Teeracle.
pub trait ExportMetrics<MetricsInfo> {
	fn increment_number_requests(&self, source: String);

	fn record_response_time(&self, source: String, timer: Instant);

	fn update_exchange_rate(
		&self,
		source: String,
		exchange_rate: ExchangeRate,
		trading_pair: TradingPair,
	);

	fn update_weather(&self, source: String, metrics_info: MetricsInfo);
}

pub trait UpdateMetric<MetricInfo> {
	fn update_metric(&self, metric: OracleMetric<MetricInfo>);
}

/// Metrics exporter implementation.
pub struct MetricsExporter<OCallApi> {
	ocall_api: Arc<OCallApi>,
}

impl<OCallApi, MetricInfo> UpdateMetric<MetricInfo> for MetricsExporter<OCallApi>
where
	OCallApi: EnclaveMetricsOCallApi,
{
	fn update_metric(&self, _metric: OracleMetric<MetricInfo>) {
		// TODO: Implement me
	}
}

impl<OCallApi> MetricsExporter<OCallApi>
where
	OCallApi: EnclaveMetricsOCallApi,
{
	pub fn new(ocall_api: Arc<OCallApi>) -> Self {
		MetricsExporter { ocall_api }
	}

	fn update_metric(&self, metric: ExchangeRateOracleMetric) {
		if let Err(e) = self.ocall_api.update_metric(EnclaveMetric::ExchangeRateOracle(metric)) {
			error!("Failed to update enclave metric, sgx_status_t: {}", e)
		}
	}
}

impl<OCallApi, MetricsInfo> ExportMetrics<MetricsInfo> for MetricsExporter<OCallApi>
where
	OCallApi: EnclaveMetricsOCallApi,
{
	fn increment_number_requests(&self, source: String) {
		self.update_metric(ExchangeRateOracleMetric::NumberRequestsIncrement(source));
	}

	fn record_response_time(&self, source: String, timer: Instant) {
		self.update_metric(ExchangeRateOracleMetric::ResponseTime(
			source,
			timer.elapsed().as_millis(),
		));
	}

	fn update_exchange_rate(
		&self,
		source: String,
		exchange_rate: ExchangeRate,
		trading_pair: TradingPair,
	) {
		self.update_metric(ExchangeRateOracleMetric::ExchangeRate(
			source,
			trading_pair.key(),
			exchange_rate,
		));
	}

	fn update_weather(&self, _source: String, _metrics_info: MetricsInfo) {
		// TODO: Implement me
	}
}
