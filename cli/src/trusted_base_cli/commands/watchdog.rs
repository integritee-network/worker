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
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_sidechain_header, get_trusted_account_info},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_stf::{
	Getter, ParentchainsInfo, PublicGetter, TrustedCall, TrustedCallSigned, STF_TX_FEE_UNIT_DIVIDER,
};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use prometheus::{register_gauge, Encoder, TextEncoder};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use warp::Filter;

#[derive(Parser)]
pub struct WatchdogCommand {
	/// watchdog AccountId in ss58check format. must have enough funds on shard
	account: String,
	/// probing interval in seconds. default is 3600 (1h)
	#[clap(long)]
	interval: Option<u64>,
	/// port to use for serving prometheus metrics. default is 9090
	#[clap(long)]
	prometheus_port: Option<u16>,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl WatchdogCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.account, self.session_proxy, cli, trusted_args);

		let interval = self.interval.unwrap_or(3600);
		let account_info_getter_duration_gauge = register_gauge!(
			"trusted_getter_account_info_request_seconds",
			"Duration of the getter request operation in seconds"
		)
		.unwrap();
		let sidechain_block_header_getter_duration_gauge = register_gauge!(
			"sidechain_block_header_request_seconds",
			"Duration of the getter request operation in seconds"
		)
		.unwrap();
		let sidechain_block_number_gauge =
			register_gauge!("sidechain_block_number", "latest block number for shard").unwrap();
		let send_note_duration_gauge = register_gauge!(
			"trusted_call_send_note_request_seconds",
			"Duration of the STF send_note request operation in seconds"
		)
		.unwrap();
		let watchdog_account_balance_gauge = register_gauge!(
			"watchdog_account_trusted_balance_free",
			"Balance of the watchdog account on L2"
		)
		.unwrap();

		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
			PublicGetter::parentchains_info,
		));
		let parentchains_info: ParentchainsInfo =
			perform_trusted_operation(cli, trusted_args, &top).unwrap();
		let decimals = parentchains_info.get_shielding_target_decimals().unwrap_or(12);
		println!("Shielding target decimals: {}", decimals);

		// Create a Tokio runtime
		let rt = tokio::runtime::Runtime::new().unwrap();

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

			tokio::spawn(
				warp::serve(metrics_route)
					.run(([0, 0, 0, 0], self.prometheus_port.unwrap_or(9090))),
			);

			loop {
				// probe TrustedGetter for AccountInfo
				let getter_start_timer = Instant::now();
				let account_info = get_trusted_account_info(cli, trusted_args, &sender, &signer)
					.unwrap_or_default();
				let getter_duration = getter_start_timer.elapsed();
				println!("Getting AccountInfo took {}ms", getter_duration.as_millis());
				account_info_getter_duration_gauge.set(getter_duration.as_secs_f64());
				let decimal_balance_free =
					account_info.data.free as f64 / 10u128.pow(decimals as u32) as f64;
				let nonce = account_info.nonce;
				watchdog_account_balance_gauge.set(decimal_balance_free);
				// probe basic rpc: sidechain header
				let header_getter_start_timer = Instant::now();
				if let Ok(header) = get_sidechain_header(cli) {
					let getter_duration = header_getter_start_timer.elapsed();
					println!(
						"Getting SidechainHeader took {}ms. block number: {}",
						getter_duration.as_millis(),
						header.block_number
					);
					sidechain_block_header_getter_duration_gauge.set(getter_duration.as_secs_f64());
					sidechain_block_number_gauge.set(header.block_number as f64);
				} else {
					println!("Failed to get sidechain header");
					sidechain_block_header_getter_duration_gauge.set(f64::INFINITY);
					sidechain_block_number_gauge.set(f64::INFINITY);
				}

				// probe STF: send_note
				if decimal_balance_free < 2f64 / STF_TX_FEE_UNIT_DIVIDER as f64 {
					println!("Account has insufficient funds. Exiting.");
					send_note_duration_gauge.set(f64::INFINITY);
					break;
				};
				let top = TrustedCall::send_note(sender.clone(), sender.clone(), "W".into())
					.sign(&KeyPair::Sr25519(Box::new(signer.clone())), nonce, &mrenclave, &shard)
					.into_trusted_operation(trusted_args.direct);
				let send_note_start_timer = Instant::now();
				if send_direct_request(cli, trusted_args, &top).is_ok() {
					let send_note_duration = send_note_start_timer.elapsed();
					println!("Send note took {}ms", send_note_duration.as_millis());
					send_note_duration_gauge.set(send_note_duration.as_secs_f64());
				} else {
					println!("Failed to send note");
					send_note_duration_gauge.set(f64::INFINITY);
				}
				println!("Sleeping for {} seconds", interval);
				sleep(Duration::from_secs(interval)).await;
			}
		});
		Ok(CliResultOk::None)
	}
}
