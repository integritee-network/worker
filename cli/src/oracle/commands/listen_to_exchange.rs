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
use itp_node_api::api_client::ParentchainApi;
use itp_time_utils::{duration_now, remaining_time};
use log::{debug, info, trace};
use my_node_runtime::{Hash, RuntimeEvent};
use std::time::Duration;
use substrate_api_client::SubscribeEvents;

/// Listen to exchange rate events.
#[derive(Debug, Clone, Parser)]
pub struct ListenToExchangeRateEventsCmd {
	/// Listen for `duration` in seconds.
	duration: u64,
}

impl ListenToExchangeRateEventsCmd {
	pub fn run(&self, cli: &Cli) {
		let api = get_chain_api(cli);
		let duration = Duration::from_secs(self.duration);

		let count = count_exchange_rate_update_events(&api, duration);

		println!("Number of ExchangeRateUpdated events received : ");
		println!("   EVENTS_COUNT: {}", count);
	}
}

pub fn count_exchange_rate_update_events(api: &ParentchainApi, duration: Duration) -> u32 {
	let stop = duration_now() + duration;

	//subscribe to events
	let mut subscription = api.subscribe_events().unwrap();
	let mut count = 0;

	while remaining_time(stop).unwrap_or_default() > Duration::ZERO {
		let events_result = subscription.next_event::<RuntimeEvent, Hash>().unwrap();
		if let Ok(events) = events_result {
			for event_record in &events {
				info!("received event {:?}", event_record.event);
				if let RuntimeEvent::Teeracle(event) = &event_record.event {
					match &event {
						my_node_runtime::pallet_teeracle::Event::ExchangeRateUpdated {
							data_source,
							trading_pair,
							exchange_rate,
						} => {
							count += 1;
							debug!("Received ExchangeRateUpdated event");
							println!(
								"ExchangeRateUpdated: TRADING_PAIR : {}, SRC : {}, VALUE :{:?}",
								trading_pair, data_source, exchange_rate
							);
						},
						_ => trace!("ignoring teeracle event: {:?}", event),
					}
				}
			}
		}
	}
	debug!("Received {} ExchangeRateUpdated event(s) in total", count);
	count
}
