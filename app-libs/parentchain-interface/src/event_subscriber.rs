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
extern crate alloc;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};
use itp_node_api::api_client::AccountApi;
use itp_types::parentchain::{
	AddedSgxEnclave, BalanceTransfer, ExtrinsicFailed, Hash, ParentchainId,
};
use log::warn;
use sp_core::crypto::AccountId32;
use sp_runtime::DispatchError;
use substrate_api_client::SubscribeEvents;

pub fn subscribe_to_parentchain_events<
	ParentchainApi: AccountApi<AccountId = AccountId32> + SubscribeEvents<Hash = Hash>,
>(
	api: &ParentchainApi,
	parentchain_id: ParentchainId,
	shutdown_flag: Arc<AtomicBool>,
) {
	println!("[L1Event:{}] Subscribing to selected events", parentchain_id);
	let mut subscription = api.subscribe_events().unwrap();
	while !shutdown_flag.load(Ordering::Relaxed) {
		let events = subscription.next_events_from_metadata().unwrap().unwrap();

		for event in events.iter() {
			let event = event.unwrap();
			match event.pallet_name() {
				"System" => match event.variant_name() {
					"ExtrinsicFailed" =>
						if let Ok(Some(ev)) = event.as_event::<ExtrinsicFailed>() {
							// filter only modules of potential interest.
							// TODO: filter only extrinsics from enclave and use metadata to enrich message
							match ev.dispatch_error {
								DispatchError::Module(me) => match me.index {
									7 => (),  // Proxy
									9 => (),  // Utility
									10 => (), // Balances
									50 => (), // Teerex
									52 => (), // Teeracle
									53 => (), // Sidechain
									54 => (), // EnclaveBridge
									_ => continue,
								},
								DispatchError::BadOrigin => (),
								_ => continue,
							}
							println!("[L1Event:{}] {:?}", parentchain_id, ev);
						},
					"CodeUpdated" => {
						println!(
							"[L1Event:{}] CodeUpdated. Initiating service shutdown to allow clean restart",
							parentchain_id
						);
						shutdown_flag.store(true, Ordering::Relaxed);
					},
					"UpdateAuthorized" => warn!("[L1Event:{}] UpdateAuthorized", parentchain_id),
					_ => continue,
				},
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
	println!("[L1Event:{}] Subscription terminated", parentchain_id);
}
