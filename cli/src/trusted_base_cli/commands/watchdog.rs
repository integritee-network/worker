/*
	Copyright 2021 Integritee AG

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
	get_sender_and_signer_from_args, trusted_cli::TrustedCli,
	trusted_command_utils::get_trusted_account_info, Cli, CliResult, CliResultOk,
};
use prometheus::{register_gauge, Encoder, Gauge, TextEncoder};
use rayon::prelude::*;
use std::{
	sync::mpsc::{channel, Receiver, Sender},
	time::Instant,
};
use tokio::time::{sleep, Duration};
use warp::Filter;

#[derive(Parser)]
pub struct WatchdogCommand {
	/// watchdog AccountId in ss58check format. must have enough funds on shard
	account: String,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl WatchdogCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer) =
			get_sender_and_signer_from_args!(self.account, self.session_proxy, trusted_args);

		// Register a gauge metric
		let getter_duration_gauge = register_gauge!(
			"trusted_getter_account_info_request_seconds",
			"Duration of the getter request operation in seconds"
		)
		.unwrap();
		// Create a Tokio runtime
		let rt = tokio::runtime::Runtime::new().unwrap();

		// Start the Prometheus server and run the loop in the Tokio runtime
		rt.block_on(async {
			// Start the Prometheus server
			let metrics_route = warp::path("metrics").map(move || {
				let encoder = TextEncoder::new();
				let metric_families = prometheus::gather();
				let mut buffer = Vec::new();
				encoder.encode(&metric_families, &mut buffer).unwrap();
				warp::http::Response::builder()
					.header("Content-Type", encoder.format_type())
					.body(buffer)
			});

			tokio::spawn(warp::serve(metrics_route).run(([0, 0, 0, 0], 9090)));

			loop {
				let getter_start_timer = Instant::now();
				let _info = get_trusted_account_info(cli, trusted_args, &sender, &signer)
					.map(|info| info.nonce)
					.unwrap_or_default();
				let getter_duration = getter_start_timer.elapsed();
				println!("Getting AccountInfo took {}ms", getter_duration.as_millis());
				getter_duration_gauge.set(getter_duration.as_secs_f64());
			}
		});
		Ok(CliResultOk::None)
	}
}
