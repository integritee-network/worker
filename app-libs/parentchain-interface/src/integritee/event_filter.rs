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
//! Various way to filter Parentchain events

use itc_parentchain_indirect_calls_executor::event_filter::ToEvents;
use itp_api_client_types::Events;

use itp_types::{
	parentchain::{
		BalanceTransfer, ExtrinsicFailed, ExtrinsicStatus, ExtrinsicSuccess, FilterEvents,
	},
	H256,
};
use std::vec::Vec;

#[derive(Clone)]
pub struct FilterableEvents(pub Events<H256>);

// todo: improve: https://github.com/integritee-network/worker/pull/1378#discussion_r1393933766
impl ToEvents<Events<H256>> for FilterableEvents {
	fn to_events(&self) -> &Events<H256> {
		&self.0
	}
}

impl From<Events<H256>> for FilterableEvents {
	fn from(ev: Events<H256>) -> Self {
		Self(ev)
	}
}

impl FilterEvents for FilterableEvents {
	type Error = itc_parentchain_indirect_calls_executor::Error;

	fn get_extrinsic_statuses(&self) -> core::result::Result<Vec<ExtrinsicStatus>, Self::Error> {
		Ok(self
			.to_events()
			.iter()
			.filter_map(|ev| {
				ev.and_then(|ev| {
					if (ev.as_event::<ExtrinsicSuccess>()?).is_some() {
						return Ok(Some(ExtrinsicStatus::Success))
					}

					if (ev.as_event::<ExtrinsicFailed>()?).is_some() {
						return Ok(Some(ExtrinsicStatus::Failed))
					}

					Ok(None)
				})
				.ok()
				.flatten()
			})
			.collect())
	}

	fn get_transfer_events(&self) -> core::result::Result<Vec<BalanceTransfer>, Self::Error> {
		Ok(self
			.to_events()
			.iter()
			.flatten() // flatten filters out the nones
			.filter_map(|ev| match ev.as_event::<BalanceTransfer>() {
				Ok(maybe_event) => maybe_event,
				Err(e) => {
					log::error!("Could not decode event: {:?}", e);
					None
				},
			})
			.collect())
	}
}
