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

//! an RPC client to Integritee using websockets
//!
//! examples
//! integritee_cli 127.0.0.1:9944 transfer //Alice 5G9RtsTbiYJYQYMHbWfyPoeuuxNaCbC16tZ2JGrZ4gRKwz14 1000
//!
#![feature(rustc_private)]
#[macro_use]
extern crate clap;
extern crate chrono;
extern crate env_logger;
extern crate log;

mod command_utils;
mod commands;
mod trusted_command_utils;
mod trusted_commands;
mod trusted_operation;

use crate::commands::Commands;
use clap::Parser;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[clap(name = "integritee-cli")]
#[clap(version = VERSION)]
#[clap(author = "Integritee AG <hello@integritee.network>")]
#[clap(about = "interact with integritee-node and workers", long_about = None)]
#[clap(after_help = "stf subcommands depend on the stf crate this has been built against")]
pub struct Cli {
	/// node url
	#[clap(short = 'u', long, default_value_t = String::from("ws://127.0.0.1"))]
	node_url: String,

	/// node port
	#[clap(short = 'p', long, default_value_t = String::from("9944"))]
	node_port: String,

	/// worker url
	#[clap(short = 'U', long, default_value_t = String::from("wss://127.0.0.1"))]
	worker_url: String,

	/// worker direct invocation port
	#[clap(short = 'P', long, default_value_t = String::from("2000"))]
	trusted_worker_port: String,

	#[clap(subcommand)]
	command: Commands,
}

fn main() {
	env_logger::init();

	let cli = Cli::parse();

	commands::match_command(&cli);
}

pub fn count_exchange_rate_update_events<P: Pair, Client: 'static>(
	api: Api<P, Client>,
	duration: Duration,
) -> u32
where
	MultiSignature: From<P::Signature>,
	Client: RpcClient + Subscriber + Send,
{
	let stop = duration_now() + duration;

	//subscribe to events
	let (events_in, events_out) = channel();
	api.subscribe_events(events_in).unwrap();
	let mut count = 0;

	while remaining_time(stop).unwrap_or_default() > Duration::ZERO {
		let event_str = events_out.recv().unwrap();
		let unhex = Vec::from_hex(event_str).unwrap();
		let mut event_records_encoded = unhex.as_slice();
		let events_result =
			Vec::<frame_system::EventRecord<Event, Hash>>::decode(&mut event_records_encoded);
		if let Ok(events) = events_result {
			for event_record in &events {
				info!("received event {:?}", event_record.event);
				if let Event::Teeracle(event) = &event_record.event {
					match &event {
						my_node_runtime::pallet_teeracle::Event::ExchangeRateUpdated(
							src,
							trading_pair,
							exchange_rate,
						) => {
							count += 1;
							println!(
								"ExchangeRateUpdated: TRADING_PAIR : {}, SRC : {}, VALUE :{:?}",
								trading_pair, src, exchange_rate
							);
						},
						_ => debug!("ignoring teeracle event: {:?}", event),
					}
				}
			}
		}
	}
	count
}
