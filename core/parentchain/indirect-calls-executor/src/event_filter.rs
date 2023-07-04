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
use itp_types::H256;
use std::vec::Vec;

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
pub trait FilterEvents {
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>>;
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
}

pub struct MockEvents;

impl FilterEvents for MockEvents {
	fn get_extrinsic_statuses(&self) -> Result<Vec<ExtrinsicStatus>> {
		Ok(Vec::from([ExtrinsicStatus::Success]))
	}
}
