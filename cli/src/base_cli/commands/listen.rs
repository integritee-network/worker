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
use ita_parentchain_interface::integritee::parachain::{Hash, RuntimeEvent};
use log::*;
use substrate_api_client::SubscribeEvents;

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
		info!("Subscribing to events");
		let count = 0u32;
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

			let event_results = subscription.next_events::<RuntimeEvent, Hash>().unwrap();
			blocks += 1;
			match event_results {
				Ok(evts) =>
					for evr in &evts {
						println!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
					},
				Err(_) => error!("couldn't decode event record list"),
			}
		}
	}
}
