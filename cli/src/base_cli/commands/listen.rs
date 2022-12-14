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
use base58::ToBase58;
use codec::{Decode, Encode};
use log::*;
use my_node_runtime::{Hash, RuntimeEvent};
use std::{sync::mpsc::channel, vec::Vec};
use substrate_api_client::utils::FromHexString;

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
	pub(crate) fn run(&self, cli: &Cli) {
		println!("{:?} {:?}", self.events, self.blocks);
		let api = get_chain_api(cli);
		info!("Subscribing to events");
		let (events_in, events_out) = channel();
		let mut count = 0u32;
		let mut blocks = 0u32;
		api.subscribe_events(events_in).unwrap();
		loop {
			if let Some(e) = self.events {
				if count >= e {
					return
				}
			};
			if let Some(b) = self.blocks {
				if blocks >= b {
					return
				}
			};
			let event_str = events_out.recv().unwrap();
			let _unhex = Vec::from_hex(event_str).unwrap();
			let mut _er_enc = _unhex.as_slice();
			let _events =
				Vec::<frame_system::EventRecord<RuntimeEvent, Hash>>::decode(&mut _er_enc);
			blocks += 1;
			match _events {
				Ok(evts) =>
					for evr in &evts {
						println!("decoded: phase {:?} event {:?}", evr.phase, evr.event);
						match &evr.event {
							RuntimeEvent::Balances(be) => {
								println!(">>>>>>>>>> balances event: {:?}", be);
								match &be {
									pallet_balances::Event::Transfer { from, to, amount } => {
										println!("From: {:?}", from);
										println!("To: {:?}", to);
										println!("Value: {:?}", amount);
									},
									_ => {
										debug!("ignoring unsupported balances event");
									},
								}
							},
							RuntimeEvent::Teerex(ee) => {
								println!(">>>>>>>>>> integritee event: {:?}", ee);
								count += 1;
								match &ee {
									my_node_runtime::pallet_teerex::Event::AddedEnclave(
										accountid,
										url,
									) => {
										println!(
											"AddedEnclave: {:?} at url {}",
											accountid,
											String::from_utf8(url.to_vec())
												.unwrap_or_else(|_| "error".to_string())
										);
									},
									my_node_runtime::pallet_teerex::Event::RemovedEnclave(
										accountid,
									) => {
										println!("RemovedEnclave: {:?}", accountid);
									},
									my_node_runtime::pallet_teerex::Event::Forwarded(shard) => {
										println!(
											"Forwarded request for shard {}",
											shard.encode().to_base58()
										);
									},
									my_node_runtime::pallet_teerex::Event::ProcessedParentchainBlock(
										accountid,
										block_hash,
										merkle_root,
										block_number,
									) => {
										println!(
											"ProcessedParentchainBlock from {} with hash {:?}, number {} and merkle root {:?}",
											accountid, block_hash, merkle_root, block_number
										);
									},
									my_node_runtime::pallet_teerex::Event::ShieldFunds(
										incognito_account,
									) => {
										println!("ShieldFunds for {:?}", incognito_account);
									},
									my_node_runtime::pallet_teerex::Event::UnshieldedFunds(
										public_account,
									) => {
										println!("UnshieldFunds for {:?}", public_account);
									},
									_ => debug!("ignoring unsupported teerex event: {:?}", ee),
								}
							},
							RuntimeEvent::Sidechain(ee) => {
								count += 1;
								match &ee {
									my_node_runtime::pallet_sidechain::Event::ProposedSidechainBlock(
										accountid,
										block_hash,
									) => {
										println!(
											"ProposedSidechainBlock from {} with hash {:?}",
											accountid, block_hash
										);
									},
									_ => debug!("ignoring unsupported sidechain event: {:?}", ee),
								}
							},
							_ => debug!("ignoring unsupported module event: {:?}", evr.event),
						}
					},
				Err(_) => error!("couldn't decode event record list"),
			}
		}
	}
}
