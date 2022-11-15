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

use crate::{
	error::Error,
	metrics_exporter::ExportMetrics,
	traits::OracleSource,
	types::{ExchangeRate, TradingPair},
};
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
};
use std::{
	time::{Duration, Instant},
	vec::Vec,
};
use url::Url;

/// Mock metrics exporter.
#[derive(Default)]
pub(crate) struct MetricsExporterMock {
	number_requests: RwLock<u64>,
	response_times: RwLock<Vec<u128>>,
	exchange_rates: RwLock<Vec<(TradingPair, ExchangeRate)>>,
}

impl MetricsExporterMock {
	pub fn get_number_request(&self) -> u64 {
		*self.number_requests.read().unwrap()
	}

	pub fn get_response_times(&self) -> Vec<u128> {
		self.response_times.read().unwrap().clone()
	}

	pub fn get_exchange_rates(&self) -> Vec<(TradingPair, ExchangeRate)> {
		self.exchange_rates.read().unwrap().clone()
	}
}

impl<MetricsInfo> ExportMetrics<MetricsInfo> for MetricsExporterMock {
	fn increment_number_requests(&self, _source: String) {
		(*self.number_requests.write().unwrap()) += 1;
	}

	fn record_response_time(&self, _source: String, timer: Instant) {
		self.response_times.write().unwrap().push(timer.elapsed().as_millis());
	}

	fn update_exchange_rate(
		&self,
		_source: String,
		exchange_rate: ExchangeRate,
		trading_pair: TradingPair,
	) {
		self.exchange_rates.write().unwrap().push((trading_pair, exchange_rate));
	}

	fn update_weather(&self, _source: String, _metrics_info: MetricsInfo) {}
}

/// Mock oracle source.
#[derive(Default)]
pub(crate) struct OracleSourceMock;

impl<OracleSourceInfo> OracleSource<OracleSourceInfo> for OracleSourceMock {
	type OracleRequestResult = Result<f32, Error>;

	fn metrics_id(&self) -> String {
		"source_mock".to_string()
	}

	fn request_timeout(&self) -> Option<Duration> {
		None
	}

	fn base_url(&self) -> Result<Url, Error> {
		Url::parse("https://mock.base.url").map_err(|e| Error::Other(format!("{:?}", e).into()))
	}

	fn root_certificate_content(&self) -> String {
		"MOCK_CERTIFICATE".to_string()
	}
	fn execute_exchange_rate_request(
		&self,
		_rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		_trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error> {
		Ok(ExchangeRate::from_num(42.3f32))
	}

	fn execute_request(
		_rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		_source_info: OracleSourceInfo,
	) -> Self::OracleRequestResult {
		Ok(42.3f32)
	}
}
