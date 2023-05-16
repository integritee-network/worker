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

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexport_prelude::*;

use crate::{
    error::Result,
	error::Error,
};
use itp_api_client_types::{EventDetails, Events, Metadata, StaticEvent};
use codec::{Decode, Encode};
use itp_types::H256;
use std::vec::Vec;

#[derive(Decode, Encode, Debug)]
pub struct ExtrinsicSuccess;
impl StaticEvent for ExtrinsicSuccess {
	const PALLET: &'static str = "System";
	const EVENT: &'static str = "ExtrinsicSuccess";
}

#[derive(Decode, Encode)]
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

pub struct EventFilter;

impl EventFilter {

    pub fn get_extrinsic_statuses(events: Events<H256>) -> Result<Vec<ExtrinsicStatus>> {
        Ok(events.iter().filter_map(|ev| {
            ev.and_then(|ev| {

                if let Some(_) = ev.as_event::<ExtrinsicSuccess>()? {
                    return Ok(Some(ExtrinsicStatus::Success));
                }

                if let Some(_) = ev.as_event::<ExtrinsicFailed>()? {
                    return Ok(Some(ExtrinsicStatus::Failed));
                }

                Ok(None)
            }).ok().flatten()
        }).collect())
    }

}


