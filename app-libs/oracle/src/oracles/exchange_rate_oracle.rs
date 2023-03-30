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
	traits::OracleSource,
	types::{ExchangeRate, TradingInfo, TradingPair},
	Error,
};
use itc_rest_client::{
	http_client::{HttpClient, SendWithCertificateVerification},
	rest_client::RestClient,
};
use log::*;
use std::{
	sync::Arc,
	thread,
	time::{Duration, Instant},
};
use url::Url;

#[allow(unused)]
pub struct ExchangeRateOracle<OracleSourceType, MetricsExporter> {
	oracle_source: OracleSourceType,
	metrics_exporter: Arc<MetricsExporter>,
}

impl<OracleSourceType, MetricsExporter> ExchangeRateOracle<OracleSourceType, MetricsExporter> {
	pub fn new(oracle_source: OracleSourceType, metrics_exporter: Arc<MetricsExporter>) -> Self {
		ExchangeRateOracle { oracle_source, metrics_exporter }
	}
}

pub trait GetExchangeRate {
	/// Get the cryptocurrency/fiat_currency exchange rate
	fn get_exchange_rate(&self, trading_pair: TradingPair) -> Result<(ExchangeRate, Url), Error>;
}

impl<OracleSourceType, MetricsExporter> GetExchangeRate
	for ExchangeRateOracle<OracleSourceType, MetricsExporter>
where
	OracleSourceType: OracleSource<TradingInfo>,
	MetricsExporter: ExportMetrics<TradingInfo>,
{
	fn get_exchange_rate(&self, trading_pair: TradingPair) -> Result<(ExchangeRate, Url), Error> {
		let source_id = self.oracle_source.metrics_id();
		self.metrics_exporter.increment_number_requests(source_id.clone());

		let base_url = self.oracle_source.base_url()?;
		let root_certificate = self.oracle_source.root_certificate_content();
		let request_timeout = self.oracle_source.request_timeout();

		debug!("Get exchange rate from URI: {}, trading pair: {:?}", base_url, trading_pair);

		let http_client = HttpClient::new(
			SendWithCertificateVerification::new(root_certificate),
			true,
			request_timeout,
			None,
			None,
		);
		let mut rest_client = RestClient::new(http_client, base_url.clone());

		// Due to possible failures that may be temporarily this function tries to fetch the exchange rates `number_of_tries` times.
		// If it still fails for the last attempt, then only in that case will it be considered a non-recoverable error.
		let number_of_tries = 3;
		let timer_start = Instant::now();

		let mut tries = 0;
		let result = loop {
			tries += 1;
			let exchange_result = self
				.oracle_source
				.execute_exchange_rate_request(&mut rest_client, trading_pair.clone());

			match exchange_result {
				Ok(exchange_rate) => {
					self.metrics_exporter.record_response_time(source_id.clone(), timer_start);
					self.metrics_exporter.update_exchange_rate(
						source_id,
						exchange_rate,
						trading_pair,
					);

					debug!("Successfully executed exchange rate request");
					break Ok((exchange_rate, base_url))
				},
				Err(e) =>
					if tries < number_of_tries {
						error!(
							"Getting exchange rate from {} failed with {}, trying again in {:#?}.",
							&base_url, e, request_timeout
						);
						debug!("Check that the API endpoint is available, for coingecko: https://status.coingecko.com/");
						thread::sleep(
							request_timeout.unwrap_or_else(|| Duration::from_secs(number_of_tries)),
						);
					} else {
						error!(
							"Getting exchange rate from {} failed {} times, latest error is: {}.",
							&base_url, number_of_tries, &e
						);
						break Err(e)
					},
			}
		};
		result
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
