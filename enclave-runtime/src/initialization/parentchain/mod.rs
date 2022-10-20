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

use crate::{error::Result, LightClientInitParams};
use itp_settings::worker_mode::ProvideWorkerMode;
use sp_runtime::traits::Header as HeaderTrait;
use std::vec::Vec;

mod common;
pub mod parachain;
pub mod solochain;

pub(crate) fn init_parentchain_components<
	Header: HeaderTrait,
	WorkerModeProvider: ProvideWorkerMode,
>(
	params: LightClientInitParams<Header>,
) -> Result<Vec<u8>> {
	let encoded_latest_header = match params {
		LightClientInitParams::Grandpa { .. } =>
			solochain::FullSolochainHandler::init::<WorkerModeProvider>(params)?,
		LightClientInitParams::Parachain { .. } =>
			parachain::FullParachainHandler::init::<WorkerModeProvider>(params)?,
	};

	Ok(encoded_latest_header)
}
