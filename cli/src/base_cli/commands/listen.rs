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

use crate::{command_utils::get_chain_api, Cli, CliResult, CliResultOk};
use ita_parentchain_interface::integritee::{parachain, solochain};
use log::*;
use substrate_api_client::{ac_node_api::Phase::ApplyExtrinsic, SubscribeEvents};

#[derive(Parser)]
pub struct ListenCommand {
	/// exit after given number of parentchain events
	#[clap(short, long = "exit-after")]
	events: Option<u32>,

	/// exit after given number of blocks
	#[clap(short, long = "await-blocks")]
	blocks: Option<u32>,
}

impl ListenCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		println!("{:?} {:?}", self.events, self.blocks);
		let api = get_chain_api(cli);
		info!("Subscribing to events (solo or para)");
		let mut count = 0u32;
		let mut blocks = 0u32;
		let mut subscription = api.subscribe_events().unwrap();
		loop {
			if let Some(e) = self.events {
				if count >= e {
					return Ok(CliResultOk::None)
				}
			};
			if let Some(b) = self.blocks {
				if blocks >= b {
					return Ok(CliResultOk::None)
				}
			};

			let maybe_event_results_solo =
				subscription.next_events::<solochain::RuntimeEvent, solochain::Hash>();
			let maybe_event_results_para =
				subscription.next_events::<parachain::RuntimeEvent, parachain::Hash>();

			blocks += 1;
			match maybe_event_results_solo {
				Some(Ok(evts)) => {
					for evr in &evts {
						if evr.phase == ApplyExtrinsic(0) {
							// not interested in intrinsics
							continue
						}
						println!("decoded solo: phase {:?} event {:?}", evr.phase, evr.event);
						count += 1;
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
						count += 1;
					},
				Some(_) => debug!("couldn't decode para event record list"),
				None => debug!("couldn't decode para event record list"),
			}
		}
	}
}
