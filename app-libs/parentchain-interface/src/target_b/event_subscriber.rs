use crate::print_events;
use core::fmt::Debug;
use itc_parentchain::primitives::ParentchainInitParams;
use itp_api_client_types::ParentchainApi;
use itp_types::parentchain::ParentchainId;
use regex::Regex;
use substrate_api_client::{
	ac_node_api::{EventRecord, Phase::ApplyExtrinsic},
	SubscribeEvents,
};

const PARENTCHAIN_NAME: &str = "TargetB";
pub fn subscribe_to_parentchain_events(
	api: &ParentchainApi,
	parentchain_init_params: ParentchainInitParams,
) {
	println!("[L1Event:{}] Subscribing to events", PARENTCHAIN_NAME);
	let mut subscription = api.subscribe_events().unwrap();
	loop {
		if parentchain_init_params.is_parachain() {
			if let Some(Ok(events)) =
				subscription.next_events::<super::parachain::RuntimeEvent, super::parachain::Hash>()
			{
				print_events::<super::parachain::RuntimeEvent, super::parachain::Hash>(
					events,
					format!("[L1Event:{}Para]", PARENTCHAIN_NAME),
				)
			}
		} else {
			if let Some(Ok(events)) =
				subscription.next_events::<super::solochain::RuntimeEvent, super::solochain::Hash>()
			{
				print_events::<super::solochain::RuntimeEvent, super::solochain::Hash>(
					events,
					format!("[L1Event:{}Solo]", PARENTCHAIN_NAME),
				)
			}
		}
	}
}
