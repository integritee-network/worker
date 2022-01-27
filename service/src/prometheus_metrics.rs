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

use crate::error::{Error, ServiceResult};
use lazy_static::lazy_static;
use log::*;
use prometheus::{proto::MetricFamily, register_int_gauge, IntGauge};
use std::{net::SocketAddr, time::SystemTime};
use warp::{Filter, Rejection, Reply};

lazy_static! {
	static ref ELAPSED_SECONDS: IntGauge =
		register_int_gauge!("uptime_seconds", "Uptime of service in seconds").unwrap();
	static ref SERVICE_START_TIME: SystemTime = SystemTime::now();
}

pub async fn start_prometheus_metrics_server(port: u16) -> ServiceResult<()> {
	let metrics_route = warp::path!("metrics").and_then(metrics_handler);
	let socket_addr: SocketAddr = ([0, 0, 0, 0], port).into();

	info!("Initializing prometheus metrics");
	update_metrics();

	info!("Running prometheus metrics server on: {:?}", socket_addr);

	warp::serve(metrics_route).run(socket_addr).await;

	info!("Prometheus web server shut down");
	Ok(())
}

async fn metrics_handler() -> Result<impl Reply, Rejection> {
	update_metrics();

	let default_metrics = match gather_metrics_into_reply(&prometheus::gather()) {
		Ok(r) => r,
		Err(e) => {
			error!("Failed to gather prometheus metrics: {:?}", e);
			String::default()
		},
	};

	Ok(default_metrics)
}

fn update_metrics() {
	let elapsed_seconds = SERVICE_START_TIME
		.elapsed()
		.map(|t| t.as_secs())
		.map_err(|e| error!("Failed to compute elapsed time metric: {:?}, returning 0", e))
		.unwrap_or_default();
	ELAPSED_SECONDS.set(elapsed_seconds as i64);
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
