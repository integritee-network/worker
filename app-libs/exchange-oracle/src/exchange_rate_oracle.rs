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

use crate::{
	metrics_exporter::ExportMetrics,
	types::{ExchangeRate, TradingPair},
	Error, GetExchangeRate,
};
use core::time::Duration;
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
};
use log::*;
use std::{string::String, sync::Arc, time::Instant};
use url::Url;

/// Oracle source trait used by the `ExchangeRateOracle` (strategy pattern).
pub trait OracleSource: Default {
	fn metrics_id(&self) -> String;

	fn request_timeout(&self) -> Option<Duration>;

	fn base_url(&self) -> Result<Url, Error>;

	/// The server's root certificate. A valid certificate is required to open a tls connection
	fn root_certificate_content(&self) -> String;

	fn execute_exchange_rate_request(
		&self,
		rest_client: &mut RestClient<HttpClient<SendWithCertificateVerification>>,
		trading_pair: TradingPair,
	) -> Result<ExchangeRate, Error>;
}

pub struct ExchangeRateOracle<OracleSourceType, MetricsExporter> {
	oracle_source: OracleSourceType,
	metrics_exporter: Arc<MetricsExporter>,
}

impl<OracleSourceType, MetricsExporter> ExchangeRateOracle<OracleSourceType, MetricsExporter>
where
	OracleSourceType: OracleSource,
	MetricsExporter: ExportMetrics,
{
	pub fn new(oracle_source: OracleSourceType, metrics_exporter: Arc<MetricsExporter>) -> Self {
		ExchangeRateOracle { oracle_source, metrics_exporter }
	}
}

impl<OracleSourceType, MetricsExporter> GetExchangeRate
	for ExchangeRateOracle<OracleSourceType, MetricsExporter>
where
	OracleSourceType: OracleSource,
	MetricsExporter: ExportMetrics,
{
	fn get_exchange_rate(&self, trading_pair: TradingPair) -> Result<(ExchangeRate, Url), Error> {
		let source_id = self.oracle_source.metrics_id();
		self.metrics_exporter.increment_number_requests(source_id.clone());

		let base_url = self.oracle_source.base_url()?;
		let root_certificate = self.oracle_source.root_certificate_content();

		debug!("Get exchange rate from URI: {}, trading pair: {:?}", base_url, trading_pair);

		let http_client = HttpClient::new(
			SendWithCertificateVerification::new(root_certificate),
			true,
			self.oracle_source.request_timeout(),
			None,
			None,
		);
		let mut rest_client = RestClient::new(http_client, base_url.clone());

		let timer_start = Instant::now();

		match self
			.oracle_source
			.execute_exchange_rate_request(&mut rest_client, trading_pair.clone())
		{
			Ok(exchange_rate) => {
				self.metrics_exporter.record_response_time(source_id.clone(), timer_start);
				self.metrics_exporter
					.update_exchange_rate(source_id, exchange_rate, trading_pair);

				debug!("Successfully executed exchange rate request");
				Ok((exchange_rate, base_url))
			},
			Err(e) => Err(e),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mock::{MetricsExporterMock, OracleSourceMock};

	type TestOracle = ExchangeRateOracle<OracleSourceMock, MetricsExporterMock>;

	#[test]
	fn get_exchange_rate_updates_metrics() {
		let metrics_exporter = Arc::new(MetricsExporterMock::default());
		let test_client = TestOracle::new(OracleSourceMock {}, metrics_exporter.clone());

		let trading_pair =
			TradingPair { crypto_currency: "BTC".to_string(), fiat_currency: "USD".to_string() };
		let _bit_usd = test_client.get_exchange_rate(trading_pair.clone()).unwrap();

		assert_eq!(1, metrics_exporter.get_number_request());
		assert_eq!(1, metrics_exporter.get_response_times().len());
		assert_eq!(1, metrics_exporter.get_exchange_rates().len());

		let (metric_trading_pair, exchange_rate) =
			metrics_exporter.get_exchange_rates().first().unwrap().clone();

		assert_eq!(trading_pair, metric_trading_pair);
		assert_eq!(ExchangeRate::from_num(42.3f32), exchange_rate);
	}
}
