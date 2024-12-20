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

use crate::{command_utils::get_chain_api, Cli};
use ita_parentchain_interface::integritee::api_client_types::IntegriteeApi;
use itp_time_utils::{duration_now, remaining_time};
use itp_types::parentchain::OracleUpdated;
use log::*;
use std::time::Duration;
use substrate_api_client::SubscribeEvents;

/// Listen to exchange rate events.
#[derive(Debug, Clone, Parser)]
pub struct ListenToOracleEventsCmd {
	/// Listen for `duration` in seconds.
	duration: u64,
}

type EventCount = u32;
impl ListenToOracleEventsCmd {
	pub fn run(&self, cli: &Cli) {
		let api = get_chain_api(cli);
		let duration = Duration::from_secs(self.duration);
		let count = count_oracle_update_events(&api, duration);
		println!("Number of Oracle events received : ");
		println!("   EVENTS_COUNT: {}", count);
	}
}

fn count_oracle_update_events(api: &IntegriteeApi, duration: Duration) -> EventCount {
	let stop = duration_now() + duration;

	//subscribe to events
	let mut subscription = api.subscribe_events().unwrap();
	let mut count = 0;
	while remaining_time(stop).unwrap_or_default() > Duration::ZERO {
		let events = subscription.next_events_from_metadata().unwrap().unwrap();
		for event in events.iter() {
			let event = event.unwrap();
			match event.pallet_name() {
				"Teeracle" => match event.variant_name() {
					"OracleUpdated" =>
						if let Ok(Some(ev)) = event.as_event::<OracleUpdated>() {
							count += 1;
							println!(
								"OracleUpdated: ORACLE_NAME : {}, SRC : {}",
								ev.oracle_data_name, ev.data_source
							);
						},
					_ => continue,
				},
				_ => continue,
			}
		}
	}
	debug!("Received {} ExchangeRateUpdated event(s) in total", count);
	count
}
