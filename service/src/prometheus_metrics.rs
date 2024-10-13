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

//! Service for prometheus metrics, hosted on a http server.

#[cfg(feature = "teeracle")]
use crate::teeracle::teeracle_metrics::update_teeracle_metrics;

use crate::{
	account_funding::EnclaveAccountInfo,
	error::{Error, ServiceResult},
};
use async_trait::async_trait;
use codec::{Decode, Encode};
#[cfg(feature = "attesteer")]
use core::time::Duration;
use frame_support::scale_info::TypeInfo;
#[cfg(feature = "attesteer")]
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::{RestClient, Url as URL},
	RestGet, RestPath,
};
use itp_enclave_metrics::EnclaveMetric;
use lazy_static::lazy_static;
use log::*;
use prometheus::{
	proto::MetricFamily, register_gauge, register_histogram, register_int_counter,
	register_int_gauge, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use warp::{Filter, Rejection, Reply};

const DURATION_HISTOGRAM_BUCKETS: [f64; 10] =
	[0.0001, 0.0003, 0.0009, 0.0027, 0.0081, 0.0243, 0.0729, 0.2187, 0.6561, 1.9683];
const COUNT_HISTOGRAM_BUCKETS: [f64; 12] =
	[0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0];

lazy_static! {
	/// Register all the prometheus metrics we want to monitor (aside from the default process ones).

	static ref ENCLAVE_ACCOUNT_FREE_BALANCE: IntGauge =
		register_int_gauge!("integritee_worker_enclave_account_free_balance", "Free balance of the enclave account")
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_BLOCK_HEIGHT: IntGauge =
		register_int_gauge!("integritee_worker_enclave_sidechain_block_height", "Enclave sidechain block height")
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_TOP_POOL_SIZE: IntGauge =
		register_int_gauge!("integritee_worker_enclave_sidechain_top_pool_size", "Enclave sidechain top pool size")
			.unwrap();
	static ref ENCLAVE_RPC_REQUESTS: IntCounter =
		register_int_counter!("integritee_worker_enclave_rpc_requests", "Enclave RPC requests")
			.unwrap();
	static ref ENCLAVE_RPC_TC_RECEIVED: IntCounter =
		register_int_counter!("integritee_worker_enclave_rpc_tc_received", "Enclave RPC: how many trusted calls have been received via rpc")
			.unwrap();
	static ref ENCLAVE_STF_STATE_UPDATE_EXECUTION_DURATION: Histogram =
		register_histogram!(HistogramOpts::new("integritee_worker_enclave_stf_state_update_execution_duration", "Enclave STF: state update execution duration from before on_initialize to after on_finalize")
		.buckets(DURATION_HISTOGRAM_BUCKETS.into()))
			.unwrap();
	static ref ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_SUCCESSFUL_COUNT: Histogram =
		register_histogram!(HistogramOpts::new("integritee_worker_enclave_stf_state_update_executed_calls_successful_count", "Enclave STF: how many calls have successfully been executed per update proposal")
		.buckets(COUNT_HISTOGRAM_BUCKETS.into()))
			.unwrap();
	static ref ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_FAILED_COUNT: Histogram =
		register_histogram!(HistogramOpts::new("integritee_worker_enclave_stf_state_update_executed_calls_failed_count", "Enclave STF: how many calls have failed during execution per update proposal")
		.buckets(COUNT_HISTOGRAM_BUCKETS.into()))
			.unwrap();
	static ref ENCLAVE_STF_TOTAL_ISSUANCE: Gauge =
		register_gauge!("integritee_worker_enclave_stf_total_issuance", "Enclave stf total issuance assuming its native token")
			.unwrap();
	static ref ENCLAVE_FINGERPRINT: IntCounter =
		register_int_counter!("integritee_worker_enclave_fingerprint", "Enclave fingerprint AKA MRENCLAVE")
			.unwrap();
}

pub async fn start_metrics_server<MetricsHandler>(
	metrics_handler: Arc<MetricsHandler>,
	port: u16,
) -> ServiceResult<()>
where
	MetricsHandler: HandleMetrics + Send + Sync + 'static,
{
	let metrics_route = warp::path!("metrics").and_then(move || {
		let handler_clone = metrics_handler.clone();
		async move { handler_clone.handle_metrics().await }
	});
	let socket_addr: SocketAddr = ([0, 0, 0, 0], port).into();

	info!("Running prometheus metrics server on: {:?}", socket_addr);
	warp::serve(metrics_route).run(socket_addr).await;

	info!("Prometheus metrics server shut down");
	Ok(())
}

#[async_trait]
pub trait HandleMetrics {
	type ReplyType: Reply;

	async fn handle_metrics(&self) -> Result<Self::ReplyType, Rejection>;
}

/// Metrics handler implementation.
pub struct MetricsHandler<Wallet> {
	enclave_wallet: Arc<Wallet>,
}

#[async_trait]
impl<Wallet> HandleMetrics for MetricsHandler<Wallet>
where
	Wallet: EnclaveAccountInfo + Send + Sync,
{
	type ReplyType = String;

	async fn handle_metrics(&self) -> Result<Self::ReplyType, Rejection> {
		self.update_metrics().await;

		let default_metrics = match gather_metrics_into_reply(&prometheus::gather()) {
			Ok(r) => r,
			Err(e) => {
				error!("Failed to gather prometheus metrics: {:?}", e);
				String::default()
			},
		};

		Ok(default_metrics)
	}
}

impl<Wallet> MetricsHandler<Wallet>
where
	Wallet: EnclaveAccountInfo + Send + Sync,
{
	pub fn new(enclave_wallet: Arc<Wallet>) -> Self {
		MetricsHandler { enclave_wallet }
	}

	async fn update_metrics(&self) {
		match self.enclave_wallet.free_balance() {
			Ok(b) => {
				ENCLAVE_ACCOUNT_FREE_BALANCE.set(b as i64);
			},
			Err(e) => {
				error!("Failed to fetch free balance metric, value will not be updated: {:?}", e);
			},
		}
	}
}

fn gather_metrics_into_reply(metrics: &[MetricFamily]) -> ServiceResult<String> {
	use prometheus::Encoder;
	let encoder = prometheus::TextEncoder::new();

	let mut buffer = Vec::new();
	encoder.encode(metrics, &mut buffer).map_err(|e| {
		Error::Custom(format!("Failed to encode prometheus metrics: {:?}", e).into())
	})?;

	let result_string = String::from_utf8(buffer).map_err(|e| {
		Error::Custom(
			format!("Failed to convert Prometheus encoded metrics to UTF8: {:?}", e).into(),
		)
	})?;

	Ok(result_string)
}

/// Trait to receive metric updates from inside the enclave.
pub trait ReceiveEnclaveMetrics {
	fn receive_enclave_metric(&self, metric: EnclaveMetric) -> ServiceResult<()>;
}

pub struct EnclaveMetricsReceiver;

impl ReceiveEnclaveMetrics for EnclaveMetricsReceiver {
	fn receive_enclave_metric(&self, metric: EnclaveMetric) -> ServiceResult<()> {
		match metric {
			EnclaveMetric::SetSidechainBlockHeight(h) =>
				ENCLAVE_SIDECHAIN_BLOCK_HEIGHT.set(h as i64),
			EnclaveMetric::TopPoolSizeSet(pool_size) =>
				ENCLAVE_SIDECHAIN_TOP_POOL_SIZE.set(pool_size as i64),
			EnclaveMetric::TopPoolSizeIncrement => ENCLAVE_SIDECHAIN_TOP_POOL_SIZE.inc(),
			EnclaveMetric::TopPoolSizeDecrement => ENCLAVE_SIDECHAIN_TOP_POOL_SIZE.dec(),
			EnclaveMetric::RpcRequestsIncrement => ENCLAVE_RPC_REQUESTS.inc(),
			EnclaveMetric::RpcTrustedCallsIncrement => ENCLAVE_RPC_TC_RECEIVED.inc(),
			EnclaveMetric::StfStateUpdateExecutionDuration(duration) =>
				ENCLAVE_STF_STATE_UPDATE_EXECUTION_DURATION.observe(duration.as_secs_f64()),
			EnclaveMetric::StfStateUpdateExecutedCallsSuccessfulCount(count) =>
				ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_SUCCESSFUL_COUNT.observe(count.into()),
			EnclaveMetric::StfStateUpdateExecutedCallsFailedCount(count) =>
				ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_FAILED_COUNT.observe(count.into()),
			EnclaveMetric::StfTotalIssuanceSet(balance) => ENCLAVE_STF_TOTAL_ISSUANCE.set(balance),
			#[cfg(feature = "teeracle")]
			EnclaveMetric::ExchangeRateOracle(m) => update_teeracle_metrics(m)?,
			#[cfg(not(feature = "teeracle"))]
			EnclaveMetric::ExchangeRateOracle(_) => {
				error!("Received Teeracle metric, but Teeracle feature is not enabled, ignoring metric item.")
			},
		}
		Ok(())
	}
}

// Data structure that matches with REST API JSON

#[derive(Serialize, Deserialize, Debug)]
struct PrometheusMarblerunEvents(pub Vec<PrometheusMarblerunEvent>);

#[cfg(feature = "attesteer")]
impl RestPath<&str> for PrometheusMarblerunEvents {
	fn get_path(path: &str) -> Result<String, itc_rest_client::error::Error> {
		Ok(format!("{}", path))
	}
}

#[cfg(feature = "attesteer")]
pub fn fetch_marblerun_events(base_url: &str) -> Result<Vec<PrometheusMarblerunEvent>, Error> {
	let base_url = URL::parse(&base_url).map_err(|e| {
		Error::Custom(
			format!("Failed to parse marblerun prometheus endpoint base URL: {:?}", e).into(),
		)
	})?;
	let timeout = 3u64;
	let http_client =
		HttpClient::new(DefaultSend {}, true, Some(Duration::from_secs(timeout)), None, None);

	let mut rest_client = RestClient::new(http_client, base_url.clone());
	let events: PrometheusMarblerunEvents = rest_client.get("events").map_err(|e| {
		Error::Custom(
			format!("Failed to fetch marblerun prometheus events from: {}, error: {}", base_url, e)
				.into(),
		)
	})?;

	Ok(events.0)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
pub struct PrometheusMarblerunEvent {
	pub time: String,
	pub activation: PrometheusMarblerunEventActivation,
}

#[cfg(feature = "attesteer")]
impl PrometheusMarblerunEvent {
	pub fn get_quote_without_prepended_bytes(&self) -> &[u8] {
		let marblerun_magic_prepended_header_size = 16usize;
		&self.activation.quote.as_bytes()[marblerun_magic_prepended_header_size..]
	}
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Encode, Decode, TypeInfo)]
#[serde(rename_all = "camelCase")]
pub struct PrometheusMarblerunEventActivation {
	pub marble_type: String,
	pub uuid: String,
	pub quote: String,
}
