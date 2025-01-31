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
	account_funding::{AccountAndRole, ParentchainAccountInfo, ParentchainAccountInfoProvider},
	error::{Error, ServiceResult},
	sidechain_setup::{
		ParentchainIntegriteeSidechainInfo, ParentchainIntegriteeSidechainInfoProvider,
	},
};
use async_trait::async_trait;
use base58::ToBase58;
use codec::{Decode, Encode};
#[cfg(feature = "attesteer")]
use core::time::Duration;
use enclave_bridge_primitives::ShardIdentifier;
use frame_support::scale_info::TypeInfo;
use ita_parentchain_interface::{
	integritee::api_client_types::IntegriteeApi, target_a::api_client_types::TargetAApi,
	target_b::api_client_types::TargetBApi,
};
#[cfg(feature = "attesteer")]
use itc_rest_client::{
	http_client::{DefaultSend, HttpClient},
	rest_client::{RestClient, Url as URL},
	RestGet, RestPath,
};

use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_enclave_metrics::EnclaveMetric;
use itp_settings::worker_mode::WorkerModeProvider;
use itp_types::{parentchain::ParentchainId, EnclaveFingerprint};
use lazy_static::lazy_static;
use log::*;
use prometheus::{
	proto::MetricFamily, register_gauge, register_gauge_vec, register_histogram,
	register_histogram_vec, register_int_counter, register_int_counter_vec, register_int_gauge,
	register_int_gauge_vec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter,
	IntCounterVec, IntGauge, IntGaugeVec,
};
use serde::{Deserialize, Serialize};
use sp_core::crypto::AccountId32;
use std::{fmt::Debug, net::SocketAddr, sync::Arc};
use tokio::runtime::Handle;
use warp::{Filter, Rejection, Reply};

const DURATION_HISTOGRAM_BUCKETS: [f64; 10] =
	[0.0001, 0.0003, 0.0009, 0.0027, 0.0081, 0.0243, 0.0729, 0.2187, 0.6561, 1.9683];
const SLOT_TIME_HISTOGRAM_BUCKETS: [f64; 10] = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
const COUNT_HISTOGRAM_BUCKETS: [f64; 12] =
	[0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 512.0, 1024.0];

lazy_static! {
	// Register all the prometheus metrics we want to monitor (aside from the default process ones).
	static ref ACCOUNT_FREE_BALANCE: GaugeVec =
		register_gauge_vec!("integritee_worker_account_free_balance", "Free balance of an account on a parentchain with a role (lossy f64)", &["parentchain","role"])
			.unwrap();
	static ref ENCLAVE_TOP_POOL_A_PRIORI_SIZE: IntGauge =
		register_int_gauge!("integritee_worker_enclave_top_pool_a_priori_size", "pending TOPs in pool before executing the block")
			.unwrap();
	static ref ENCLAVE_RPC_REQUESTS: IntCounter =
		register_int_counter!("integritee_worker_enclave_rpc_requests", "Enclave RPC requests")
			.unwrap();
	static ref ENCLAVE_RPC_TC_RECEIVED: IntCounter =
		register_int_counter!("integritee_worker_enclave_rpc_tc_received", "Enclave RPC: how many trusted calls have been received via rpc")
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_BLOCK_HEIGHT: IntGauge =
		register_int_gauge!("integritee_worker_enclave_sidechain_block_height", "Enclave sidechain block height")
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_LAST_FINALIZED_BLOCK_NUMBER: IntGaugeVec =
		register_int_gauge_vec!("integritee_worker_enclave_sidechain_last_finalized_block_number", "Enclave sidechain last finalized block number (on L1)", &["shard"])
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_AURA_REMAINING_DURATIONS: HistogramVec =
		register_histogram_vec!(HistogramOpts::new("integritee_worker_enclave_sidechain_aura_remaining_durations", "Enclave Sidechain AURA durations: remaining time in slot for different stages")
		.buckets(SLOT_TIME_HISTOGRAM_BUCKETS.into()), &["stage"])
			.unwrap();
	static ref ENCLAVE_SIDECHAIN_PEER_COUNT: IntGauge =
		register_int_gauge!("integritee_worker_enclave_sidechain_peer_count", "Enclave Sidechain peer validateer count")
			.unwrap();
	static ref ENCLAVE_STF_STATE_UPDATE_EXECUTION_DURATION: Histogram =
		register_histogram!(HistogramOpts::new("integritee_worker_enclave_stf_state_update_execution_duration", "Enclave STF: state update execution duration from before on_initialize to after on_finalize")
		.buckets(DURATION_HISTOGRAM_BUCKETS.into()))
			.unwrap();
	static ref ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_COUNT: HistogramVec =
		register_histogram_vec!(HistogramOpts::new("integritee_worker_enclave_stf_state_update_attempted_calls_count", "Enclave STF: how many calls have been attempted to execute and what was the result? per update proposal")
		.buckets(COUNT_HISTOGRAM_BUCKETS.into()), &["result"])
			.unwrap();
	static ref ENCLAVE_STF_STATE_SIZE: IntGaugeVec =
		register_int_gauge_vec!("integritee_worker_enclave_stf_state_size_bytes", "Enclave STF state size in Bytes", &["shard"])
			.unwrap();
	static ref ENCLAVE_STF_RUNTIME_TOTAL_ISSUANCE: Gauge =
		register_gauge!("integritee_worker_enclave_stf_runtime_total_issuance", "Enclave stf total issuance assuming its native token")
			.unwrap();
	static ref ENCLAVE_STF_RUNTIME_PARENTCHAIN_PROCESSED_BLOCK_NUMBER: IntGaugeVec =
		register_int_gauge_vec!("integritee_worker_enclave_stf_runtime_parentchain_processed_block_number", "Enclave stf. Last processed parentchain block per parentchain", &["parentchain_id"])
			.unwrap();
	static ref ENCLAVE_LABELS: IntGaugeVec =
		register_int_gauge_vec!("integritee_worker_enclave_labels", "Enclave labels for version and fingerprint AKA MRENCLAVE", &["version", "fingerprint"])
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

/// Metrics handler implementation. This is for untrusted sources of metrics (non-enclave)
pub struct MetricsHandler<IntegriteeWallet, TargetAWallet, TargetBWallet, Sidechain> {
	integritee_wallets: Vec<Arc<IntegriteeWallet>>,
	target_a_wallets: Vec<Arc<TargetAWallet>>,
	target_b_wallets: Vec<Arc<TargetBWallet>>,
	sidechain: Arc<Sidechain>,
}

#[async_trait]
impl<IntegriteeWallet, TargetAWallet, TargetBWallet, Sidechain> HandleMetrics
	for MetricsHandler<IntegriteeWallet, TargetAWallet, TargetBWallet, Sidechain>
where
	IntegriteeWallet: ParentchainAccountInfo + Send + Sync,
	TargetAWallet: ParentchainAccountInfo + Send + Sync,
	TargetBWallet: ParentchainAccountInfo + Send + Sync,
	Sidechain: ParentchainIntegriteeSidechainInfo + Send + Sync,
{
	type ReplyType = String;

	async fn handle_metrics(&self) -> Result<Self::ReplyType, Rejection> {
		self.update_all_account_metrics().await;
		self.update_sidechain_metrics().await;

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

impl<IntegriteeWallet, TargetAWallet, TargetBWallet, Sidechain>
	MetricsHandler<IntegriteeWallet, TargetAWallet, TargetBWallet, Sidechain>
where
	IntegriteeWallet: ParentchainAccountInfo + Send + Sync,
	TargetAWallet: ParentchainAccountInfo + Send + Sync,
	TargetBWallet: ParentchainAccountInfo + Send + Sync,
	Sidechain: ParentchainIntegriteeSidechainInfo + Send + Sync,
{
	pub fn new(
		integritee_wallets: Vec<Arc<IntegriteeWallet>>,
		target_a_wallets: Vec<Arc<TargetAWallet>>,
		target_b_wallets: Vec<Arc<TargetBWallet>>,
		sidechain: Arc<Sidechain>,
	) -> Self {
		MetricsHandler { integritee_wallets, target_a_wallets, target_b_wallets, sidechain }
	}

	async fn update_all_account_metrics(&self) {
		for wallet in &self.integritee_wallets {
			if let Err(e) = Self::update_wallet_metrics(wallet).await {
				error!("Failed to update integritee wallet metrics: {:?}", e);
			}
		}

		for wallet in &self.target_a_wallets {
			if let Err(e) = Self::update_wallet_metrics(wallet).await {
				error!("Failed to update target a wallet metrics: {:?}", e);
			}
		}
		for wallet in &self.target_b_wallets {
			if let Err(e) = Self::update_wallet_metrics(wallet).await {
				error!("Failed to update target b wallet metrics: {:?}", e);
			}
		}
	}

	async fn update_wallet_metrics<W: ParentchainAccountInfo>(
		wallet: &Arc<W>,
	) -> ServiceResult<()> {
		let balance = wallet.free_balance()?;
		let parentchain_id = wallet.parentchain_id()?;
		let account_and_role = wallet.account_and_role()?;
		let decimals = wallet.decimals()?;
		ACCOUNT_FREE_BALANCE
			.with_label_values(
				[format!("{}", parentchain_id).as_str(), format!("{}", account_and_role).as_str()]
					.as_slice(),
			)
			.set(balance as f64 / (10.0f64.powf(decimals as f64)));
		Ok(())
	}

	async fn update_sidechain_metrics(&self) {
		let last_finalized_block_number = match self.sidechain.last_finalized_block_number() {
			Ok(bn) => bn,
			Err(e) => {
				error!("Failed to get last_finalized block number: {:?}", e);
				return
			},
		};
		let shard = match self.sidechain.shard() {
			Ok(shard) => shard,
			Err(e) => {
				error!("Failed to get shard: {:?}", e);
				return
			},
		};
		ENCLAVE_SIDECHAIN_LAST_FINALIZED_BLOCK_NUMBER
			.with_label_values([shard.0.to_base58().as_str()].as_slice())
			.set(last_finalized_block_number as i64);
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
				ENCLAVE_SIDECHAIN_BLOCK_HEIGHT.set(h.try_into().unwrap_or(i64::MAX)),
			EnclaveMetric::TopPoolAPrioriSizeSet(pool_size) =>
				ENCLAVE_TOP_POOL_A_PRIORI_SIZE.set(pool_size as i64),
			EnclaveMetric::RpcTrustedCallsIncrement => ENCLAVE_RPC_TC_RECEIVED.inc(),
			EnclaveMetric::RpcRequestsIncrement => ENCLAVE_RPC_REQUESTS.inc(),
			EnclaveMetric::SidechainAuraSlotRemainingTimes(label, duration) =>
				ENCLAVE_SIDECHAIN_AURA_REMAINING_DURATIONS
					.with_label_values([label.as_str()].as_slice())
					.observe(duration.as_secs_f64()),
			EnclaveMetric::StfStateUpdateExecutionDuration(duration) =>
				ENCLAVE_STF_STATE_UPDATE_EXECUTION_DURATION.observe(duration.as_secs_f64()),
			EnclaveMetric::StfStateUpdateExecutedCallsCount(success, count) =>
				ENCLAVE_STF_STATE_UPDATE_EXECUTED_CALLS_COUNT
					.with_label_values([if success { "success" } else { "failed" }].as_slice())
					.observe(u32::try_from(count).unwrap_or(u32::MAX).into()),
			EnclaveMetric::StfStateSizeSet(shard, bytes) => ENCLAVE_STF_STATE_SIZE
				.with_label_values([shard.0.to_base58().as_str()].as_slice())
				.set(bytes.try_into().unwrap_or(i64::MAX)),
			EnclaveMetric::StfRuntimeTotalIssuanceSet(balance) =>
				ENCLAVE_STF_RUNTIME_TOTAL_ISSUANCE.set(balance),
			EnclaveMetric::StfRuntimeParentchainProcessedBlockNumberSet(parentchain_id, bn) =>
				ENCLAVE_STF_RUNTIME_PARENTCHAIN_PROCESSED_BLOCK_NUMBER
					.with_label_values([format!("{}", parentchain_id).as_str()].as_slice())
					.set(bn.into()),
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

pub fn set_static_metrics(version: &str, fingerprint_b58: &str) {
	ENCLAVE_LABELS.with_label_values([version, fingerprint_b58].as_slice()).set(0)
}

pub fn set_sidechain_peer_count_metric(count: u32) {
	ENCLAVE_SIDECHAIN_PEER_COUNT.set(count as i64)
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

#[allow(clippy::too_many_arguments)]
pub fn start_prometheus_metrics_server<E>(
	enclave: &Arc<E>,
	tee_account_id: &AccountId32,
	shard: &ShardIdentifier,
	integritee_rpc_api: IntegriteeApi,
	maybe_target_a_rpc_api: Option<TargetAApi>,
	maybe_target_b_rpc_api: Option<TargetBApi>,
	shielding_target: Option<ParentchainId>,
	tokio_handle: &Handle,
	metrics_server_port: u16,
) where
	E: EnclaveBase + Sidechain,
{
	let mut integritee_account_info_providers: Vec<Arc<ParentchainAccountInfoProvider<_, _>>> =
		vec![];
	let mut target_a_account_info_providers: Vec<Arc<ParentchainAccountInfoProvider<_, _>>> =
		vec![];
	let mut target_b_account_info_providers: Vec<Arc<ParentchainAccountInfoProvider<_, _>>> =
		vec![];

	integritee_account_info_providers.push(Arc::new(ParentchainAccountInfoProvider::new(
		ParentchainId::Integritee,
		integritee_rpc_api.clone(),
		AccountAndRole::EnclaveSigner(tee_account_id.clone()),
	)));
	let shielding_target = shielding_target.unwrap_or_default();

	#[cfg(feature = "sidechain")]
	{
		let shard_vault =
			enclave.get_ecc_vault_pubkey(shard).expect("shard vault must be defined by now");

		match shielding_target {
			ParentchainId::Integritee => integritee_account_info_providers.push(Arc::new(
				ParentchainAccountInfoProvider::new(
					shielding_target,
					integritee_rpc_api.clone(),
					AccountAndRole::ShardVault(shard_vault.into()),
				),
			)),
			ParentchainId::TargetA =>
				target_a_account_info_providers.push(Arc::new(ParentchainAccountInfoProvider::new(
					shielding_target,
					maybe_target_a_rpc_api
						.clone()
						.expect("target A must be initialized to be used as shielding target"),
					AccountAndRole::ShardVault(shard_vault.into()),
				))),
			ParentchainId::TargetB =>
				target_b_account_info_providers.push(Arc::new(ParentchainAccountInfoProvider::new(
					shielding_target,
					maybe_target_b_rpc_api
						.clone()
						.expect("target B must be initialized to be used as shielding target"),
					AccountAndRole::ShardVault(shard_vault.into()),
				))),
		};
	}

	if let Some(api) = maybe_target_a_rpc_api {
		target_a_account_info_providers.push(Arc::new(ParentchainAccountInfoProvider::new(
			ParentchainId::TargetA,
			api,
			AccountAndRole::EnclaveSigner(tee_account_id.clone()),
		)))
	};
	if let Some(api) = maybe_target_b_rpc_api {
		target_b_account_info_providers.push(Arc::new(ParentchainAccountInfoProvider::new(
			ParentchainId::TargetB,
			api,
			AccountAndRole::EnclaveSigner(tee_account_id.clone()),
		)))
	};
	let sidechain_info_provider =
		Arc::new(ParentchainIntegriteeSidechainInfoProvider::new(integritee_rpc_api, *shard));

	let metrics_handler = Arc::new(MetricsHandler::new(
		integritee_account_info_providers,
		target_a_account_info_providers,
		target_b_account_info_providers,
		sidechain_info_provider,
	));

	tokio_handle.spawn(async move {
		if let Err(e) = start_metrics_server(metrics_handler, metrics_server_port).await {
			error!("Unexpected error in Prometheus metrics server: {:?}", e);
		}
	});
}
