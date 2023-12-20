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
use ita_parentchain_interface::integritee::{parachain, solochain};
use itp_node_api::api_client::ParentchainApi;
use itp_time_utils::{duration_now, remaining_time};
use log::*;
use pallet_teeracle::Event as TeeracleEvent;
use std::time::Duration;
use substrate_api_client::{ac_node_api::Phase::ApplyExtrinsic, SubscribeEvents};

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
	let mut subscription = api.subscribe_events().unwrap();
	let mut count = 0;
	while remaining_time(stop).unwrap_or_default() > Duration::ZERO {
		let maybe_event_results_solo =
			subscription.next_events::<solochain::RuntimeEvent, solochain::Hash>();
		let maybe_event_results_para =
			subscription.next_events::<parachain::RuntimeEvent, parachain::Hash>();
		match maybe_event_results_solo {
			Some(Ok(evts)) => {
				for evr in &evts {
					if evr.phase == ApplyExtrinsic(0) {
						// not interested in intrinsics
						continue
					}
					println!("decoded solo: phase {:?} event {:?}", evr.phase, evr.event);
					if let solochain::RuntimeEvent::Teeracle(TeeracleEvent::OracleUpdated {
						oracle_data_name,
						data_source,
					}) = evr.event.clone()
					{
						count += 1;
						debug!("Received OracleUpdated event");
						println!(
							"OracleUpdated: ORACLE_NAME : {}, SRC : {}",
							oracle_data_name, data_source
						);
					}
				}
				continue
			},
			Some(_) => debug!("couldn't decode event solo record list"),
			None => debug!("couldn't decode event solo record list"),
		}
		match maybe_event_results_para {
			Some(Ok(evts)) =>
				for evr in &evts {
					if evr.phase == ApplyExtrinsic(0) {
						// not interested in intrinsics
						continue
					}

					println!("decoded para: phase {:?} event {:?}", evr.phase, evr.event);
					if let parachain::RuntimeEvent::Teeracle(TeeracleEvent::OracleUpdated {
						oracle_data_name,
						data_source,
					}) = evr.event.clone()
					{
						count += 1;
						debug!("Received OracleUpdated event");
						println!(
							"OracleUpdated: ORACLE_NAME : {}, SRC : {}",
							oracle_data_name, data_source
						);
					}
				},
			Some(_) => debug!("couldn't decode para event record list"),
			None => debug!("couldn't decode para event record list"),
		}
	}
	debug!("Received {} ExchangeRateUpdated event(s) in total", count);
	count
}
