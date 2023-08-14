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
use base58::ToBase58;
use codec::Encode;
use log::*;
use my_node_runtime::{Hash, RuntimeEvent};
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

			let event_results = subscription.next_event::<RuntimeEvent, Hash>().unwrap();
			blocks += 1;
			match event_results {
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
								println!(">>>>>>>>>> integritee teerex event: {:?}", ee);
								count += 1;
								match &ee {
									my_node_runtime::pallet_teerex::Event::AddedSgxEnclave{
										registered_by,
										worker_url, ..
									}
									 => {
										println!(
											"AddedEnclave: {:?} at url {}",
											registered_by,
											String::from_utf8(worker_url.clone().unwrap_or("none".into()).to_vec())
												.unwrap_or_else(|_| "error".to_string())
										);
									},
									my_node_runtime::pallet_teerex::Event::RemovedSovereignEnclave(
										accountid,
									) => {
										println!("RemovedEnclave: {:?}", accountid);
									},
									my_node_runtime::pallet_teerex::Event::RemovedProxiedEnclave(
										eia,
									) => {
										println!("RemovedEnclave: {:?}", eia);
									},
									_ => debug!("ignoring unsupported teerex event: {:?}", ee),
								}
							},
							RuntimeEvent::EnclaveBridge(ee) => {
								println!(">>>>>>>>>> integritee enclave bridge event: {:?}", ee);
								count += 1;
								match &ee {
									my_node_runtime::pallet_enclave_bridge::Event::IndirectInvocationRegistered(shard) => {
										println!(
											"Forwarded request for shard {}",
											shard.encode().to_base58()
										);
									},
									my_node_runtime::pallet_enclave_bridge::Event::ProcessedParentchainBlock {
										shard,
										block_hash,
										trusted_calls_merkle_root,
										block_number,
									} => {
										println!(
											"ProcessedParentchainBlock from {} with hash {:?}, number {} and merkle root {:?}",
											shard, block_hash, trusted_calls_merkle_root, block_number
										);
									},
									my_node_runtime::pallet_enclave_bridge::Event::ShieldFunds {
										shard, encrypted_beneficiary, amount
									} => {
										println!("ShieldFunds on shard {:?} for {:?}. amount: {:?}", shard, encrypted_beneficiary, amount);
									},
									my_node_runtime::pallet_enclave_bridge::Event::UnshieldedFunds {
										shard, beneficiary, amount
									} => {
										println!("UnshieldFunds on shard {:?} for {:?}. amount: {:?}", shard, beneficiary, amount);
									},
									_ => debug!("ignoring unsupported enclave_bridge event: {:?}", ee),
								}
							},
							RuntimeEvent::Sidechain(ee) => {
								println!(">>>>>>>>>> integritee sidechain event: {:?}", ee);
								count += 1;
								match &ee {
									my_node_runtime::pallet_sidechain::Event::FinalizedSidechainBlock {
										shard,
										block_header_hash,
										validateer,
									} => {
										println!(
											"ProposedSidechainBlock on shard {} from {} with hash {:?}",
											shard, validateer, block_header_hash
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
