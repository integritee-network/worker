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
use itp_node_api::api_client::EventDetails;
use itp_types::parentchain::{AddedSgxEnclave, BalanceTransfer};
use log::*;
use substrate_api_client::{ac_node_api::Phase::ApplyExtrinsic, GetChainInfo, SubscribeEvents};

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

			let events = subscription.next_events_from_metadata().unwrap().unwrap();
			blocks += 1;
			let header = api.get_header(None).unwrap().unwrap();
			println!("block number (HEAD): {}", header.number);
			for event in events.iter() {
				let event = event.unwrap();
				count += 1;
				match event.pallet_name() {
					"System" => continue,
					"TransactionPayment" => continue,
					"Treasury" => continue,
					"Balances" => match event.variant_name() {
						"Deposit" => continue,
						"Withdraw" => continue,
						"Transfer" =>
							if let Ok(Some(ev)) = event.as_event::<BalanceTransfer>() {
								println!("{:?}", ev);
							},
						_ => println!("{}::{}", event.pallet_name(), event.variant_name()),
					},
					"Teerex" => match event.variant_name() {
						"AddedSgxEnclave" => {
							if let Ok(Some(ev)) = event.as_event::<AddedSgxEnclave>() {
								println!("Teerex::{:?}", ev);
							}
						},
						_ => println!("{}::{}", event.pallet_name(), event.variant_name()),
					},
					_ => println!("{}::{}", event.pallet_name(), event.variant_name()),
				}
			}
		}
	}
}
