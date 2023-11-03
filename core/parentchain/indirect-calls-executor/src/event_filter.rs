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
//! Various way to filter Parentchain events

use crate::error::Error;
use ita_stf::StfError;
use itp_api_client_types::Events;
use itp_sgx_runtime_primitives::types::{AccountId, Balance};
use itp_types::{
	parentchain::{
		BalanceTransfer, ExtrinsicFailed, ExtrinsicStatus, ExtrinsicSuccess, FilterEvents,
		HandleParentchainEvents, ParentchainError,
	},
	H256,
};
use std::{format, vec::Vec};

impl From<StfError> for Error {
	fn from(a: StfError) -> Self {
		Error::Other(format!("Error when shielding for privacy sidechain {:?}", a).into())
	}
}

#[derive(Clone)]
pub struct FilterableEvents(pub Events<H256>);

pub trait ToEvents<E> {
	fn to_events(&self) -> &E;
}

impl ToEvents<Events<H256>> for FilterableEvents {
	fn to_events(&self) -> &Events<H256> {
		&self.0
	}
}

impl FilterEvents for FilterableEvents {
	type Error = StfError;

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
				Ok(maybe_event) => {
					if maybe_event.is_none() {
						log::warn!("Transfer event does not exist in parentchain metadata");
					};
					maybe_event
				},
				Err(e) => {
					log::error!("Could not decode event: {:?}", e);
					None
				},
			})
			.collect())
	}
}

pub struct MockEvents;

impl FilterEvents for MockEvents {
	type Error = ();
	fn get_extrinsic_statuses(&self) -> core::result::Result<Vec<ExtrinsicStatus>, Self::Error> {
		Ok(Vec::from([ExtrinsicStatus::Success]))
	}

	fn get_transfer_events(&self) -> core::result::Result<Vec<BalanceTransfer>, Self::Error> {
		let transfer = BalanceTransfer {
			to: [0u8; 32].into(),
			from: [0u8; 32].into(),
			amount: Balance::default(),
		};
		Ok(Vec::from([transfer]))
	}
}

pub struct MockPrivacySidechain;

impl HandleParentchainEvents for MockPrivacySidechain {
	const SHIELDING_ACCOUNT: AccountId = AccountId::new([0u8; 32]);
	fn handle_events(
		_: impl itp_types::parentchain::FilterEvents,
	) -> core::result::Result<(), ParentchainError> {
		Ok(())
	}
	fn shield_funds(_: &AccountId, _: Balance) -> core::result::Result<(), ParentchainError> {
		Ok(())
	}
}
