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
use codec::Decode;
use itp_node_api::api_client::ParentchainApi;
use itp_time_utils::{duration_now, remaining_time};
use log::{debug, info};
use my_node_runtime::{Hash, RuntimeEvent};
use std::{sync::mpsc::channel, time::Duration};
use substrate_api_client::FromHexString;

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

fn count_oracle_update_events(api: &ParentchainApi, duration: Duration) -> EventCount {
	let stop = duration_now() + duration;

	//subscribe to events
	let (events_in, events_out) = channel();
	api.subscribe_events(events_in).unwrap();
	let mut count = 0;

	while remaining_time(stop).unwrap_or_default() > Duration::ZERO {
		let events_str = events_out.recv().unwrap();
		let events_vec_bytes = Vec::from_hex(events_str).unwrap();
		count += report_event_count(&events_vec_bytes);
	}
	debug!("Received {} ExchangeRateUpdated event(s) in total", count);
	count
}

fn report_event_count(events_bytes: &[u8]) -> EventCount {
	let event_records =
		Vec::<frame_system::EventRecord<RuntimeEvent, Hash>>::decode(&mut &events_bytes[..]);
	if event_records.is_err() {
		// Return no count if cant successfully decode event
		debug!("Could not successfully decode event_bytes {:?}", event_records);
		return 0
	}

	let mut count = 0;
	event_records.unwrap().iter().for_each(|event_record| {
		info!("received event {:?}", event_record.event);
		if let RuntimeEvent::Teeracle(event) = &event_record.event {
			match &event {
				my_node_runtime::pallet_teeracle::Event::OracleUpdated(oracle_name, src) => {
					count += 1;
					debug!("Received OracleUpdated event");
					println!("OracleUpdated: ORACLE_NAME : {}, SRC : {}", oracle_name, src);
				},
				// Can just remove this and ignore handling this case
				_ => debug!("ignoring teeracle event: {:?}", event),
			}
		}
	});
	count
}
