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

use crate::{error::ServiceResult, Error};
use itp_enclave_metrics::ExchangeRateOracleMetric;
use lazy_static::lazy_static;
use prometheus::{
	register_gauge_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
	register_int_gauge_vec, GaugeVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec,
};

lazy_static! {
	/// Register Teeracle specific metrics

	static ref EXCHANGE_RATE: GaugeVec =
		register_gauge_vec!("integritee_teeracle_exchange_rate", "Exchange rates partitioned into source and trading pair", &["source", "trading_pair"])
			.unwrap();
	static ref RESPONSE_TIME: IntGaugeVec =
		register_int_gauge_vec!("integritee_teeracle_response_times", "Response times in ms for requests that the oracle makes", &["source"])
			.unwrap();
	static ref NUMBER_OF_REQUESTS: IntCounterVec =
		register_int_counter_vec!("integritee_teeracle_number_of_requests", "Number of requests made per source", &["source"])
			.unwrap();

	static ref NUMBER_OF_REQUEST_FAILURES: IntCounter =
		register_int_counter!("integritee_teeracle_request_failures", "Number of requests that failed")
			.unwrap();

	static ref EXTRINSIC_INCLUSION_SUCCESS: IntGauge =
		register_int_gauge!("integritee_teeracle_extrinsic_inclusion_success", "1 if extrinsics was successfully finalized, 0 if not")
			.unwrap();
}

pub(super) fn increment_number_of_request_failures() {
	NUMBER_OF_REQUEST_FAILURES.inc();
}

pub(super) fn set_extrinsics_inclusion_success(is_successful: bool) {
	let success_values = if is_successful { 1 } else { 0 };
	EXTRINSIC_INCLUSION_SUCCESS.set(success_values);
}

pub fn update_teeracle_metrics(metric: ExchangeRateOracleMetric) -> ServiceResult<()> {
	match metric {
		ExchangeRateOracleMetric::ExchangeRate(source, trading_pair, exchange_rate) =>
			EXCHANGE_RATE
				.get_metric_with_label_values(&[source.as_str(), trading_pair.as_str()])
				.map(|m| m.set(exchange_rate.to_num()))
				.map_err(|e| Error::Custom(e.into()))?,

		ExchangeRateOracleMetric::ResponseTime(source, t) => RESPONSE_TIME
			.get_metric_with_label_values(&[source.as_str()])
			.map(|m| m.set(t as i64))
			.map_err(|e| Error::Custom(e.into()))?,

		ExchangeRateOracleMetric::NumberRequestsIncrement(source) => NUMBER_OF_REQUESTS
			.get_metric_with_label_values(&[source.as_str()])
			.map(|m| m.inc())
			.map_err(|e| Error::Custom(e.into()))?,
	};
	Ok(())
}
