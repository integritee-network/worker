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

use crate::error::Result;
use codec::{Decode, Encode};
use itp_api_client_types::{Events, StaticEvent};
use itp_sgx_runtime_primitives::types::{AccountId, Balance};
use itp_types::H256;
use itp_utils::stringify::account_id_to_string;
use std::{fmt::Display, format, vec::Vec};

#[derive(Encode, Decode, Debug)]
pub struct ExtrinsicSuccess;

impl StaticEvent for ExtrinsicSuccess {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicSuccess";
}

#[derive(Encode, Decode)]
pub struct ExtrinsicFailed;

impl StaticEvent for ExtrinsicFailed {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicFailed";
}

#[derive(Debug)]
pub enum ExtrinsicStatus {
	Success,
	Failed,
}

#[derive(Encode, Decode, Debug)]
pub struct BalanceTransfer {
	pub from: AccountId,
	pub to: AccountId,
	pub amount: Balance,
}

impl StaticEvent for BalanceTransfer {
	const PALLET: &'static str = "Balances";
	const EVENT: &'static str = "Transfer";
}

impl Display for BalanceTransfer {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let message = format!(
			"BalanceTransfer :: from: {}, to: {}, amount: {}",
			account_id_to_string::<AccountId>(&self.from),
			account_id_to_string::<AccountId>(&self.to),
			self.amount
		);
		write!(f, "{}", message)
	}
}

pub trait FilterEvents {
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>>;

	fn get_transfer_events(&self) -> Result<Vec<BalanceTransfer>>;
}

impl FilterEvents for Events<H256> {
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>> {
		Ok(self
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

	fn get_transfer_events(&self) -> Result<Vec<BalanceTransfer>> {
		Ok(self
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
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>> {
		Ok(Vec::from([ExtrinsicStatus::Success]))
	}

	fn get_transfer_events(&self) -> Result<Vec<BalanceTransfer>> {
		let transfer = BalanceTransfer {
			to: [0u8; 32].into(),
			from: [0u8; 32].into(),
			amount: Balance::default(),
		};
		Ok(Vec::from([transfer]))
	}
}
