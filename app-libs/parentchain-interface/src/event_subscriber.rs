/*
	Copyright 2021 Integritee AG

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

use itp_api_client_types::ParentchainApi;
use itp_types::parentchain::{AddedSgxEnclave, BalanceTransfer, ParentchainId};
use substrate_api_client::SubscribeEvents;

pub fn subscribe_to_parentchain_events(api: &ParentchainApi, parentchain_id: ParentchainId) {
	println!("[L1Event:{}] Subscribing to selected events", parentchain_id);
	let mut subscription = api.subscribe_events().unwrap();
	loop {
		let events = subscription.next_events_from_metadata().unwrap().unwrap();

		for event in events.iter() {
			let event = event.unwrap();
			match event.pallet_name() {
				"System" => continue,
				"ParaInclusion" => continue,
				"MessageQueue" => continue,
				"TransactionPayment" => continue,
				"Treasury" => continue,
				"Balances" => match event.variant_name() {
					"Deposit" => continue,
					"Withdraw" => continue,
					"Transfer" =>
						if let Ok(Some(ev)) = event.as_event::<BalanceTransfer>() {
							println!("[L1Event:{}] {:?}", parentchain_id, ev);
						},
					_ => println!(
						"[L1Event:{}] {}::{}",
						parentchain_id,
						event.pallet_name(),
						event.variant_name()
					),
				},
				"Teerex" => match event.variant_name() {
					"AddedSgxEnclave" =>
						if let Ok(Some(ev)) = event.as_event::<AddedSgxEnclave>() {
							println!("[L1Event:{}] Teerex::{:?}", parentchain_id, ev);
						},
					_ => println!(
						"[L1Event:{}] {}::{}",
						parentchain_id,
						event.pallet_name(),
						event.variant_name()
					),
				},
				_ => println!(
					"[L1Event:{}] {}::{}",
					parentchain_id,
					event.pallet_name(),
					event.variant_name()
				),
			}
		}
	}
}
