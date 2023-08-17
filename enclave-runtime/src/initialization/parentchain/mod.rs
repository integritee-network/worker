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

use crate::{
	error::Result,
	initialization::{
		global_components::{
			GLOBAL_FULL_PARACHAIN2_HANDLER_COMPONENT, GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT,
			GLOBAL_FULL_SOLOCHAIN2_HANDLER_COMPONENT, GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT,
		},
		parentchain::{parachain2::FullParachainHandler2, solochain2::FullSolochainHandler2},
	},
};
use codec::{Decode, Encode};
use itc_parentchain::{
	light_client::{concurrent_access::ValidatorAccess, LightClientState},
	primitives::{ParentchainId, ParentchainInitParams},
};
use itp_component_container::ComponentInitializer;
use itp_settings::worker_mode::ProvideWorkerMode;
use parachain::FullParachainHandler;
use solochain::FullSolochainHandler;
use std::{path::PathBuf, vec::Vec};

mod common;
pub mod parachain;
pub mod parachain2;
pub mod solochain;
pub mod solochain2;

pub(crate) fn init_parentchain_components<WorkerModeProvider: ProvideWorkerMode>(
	base_path: PathBuf,
	encoded_params: Vec<u8>,
) -> Result<Vec<u8>> {
	match ParentchainInitParams::decode(&mut encoded_params.as_slice())? {
		ParentchainInitParams::Parachain { id, params } => match id {
			ParentchainId::Teerex => {
				let handler = FullParachainHandler::init::<WorkerModeProvider>(base_path, params)?;
				let header = handler
					.validator_accessor
					.execute_on_validator(|v| v.latest_finalized_header())?;
				GLOBAL_FULL_PARACHAIN_HANDLER_COMPONENT.initialize(handler.into());
				Ok(header.encode())
			},
			ParentchainId::Secondary => {
				let handler = FullParachainHandler2::init::<WorkerModeProvider>(base_path, params)?;
				let header = handler
					.validator_accessor
					.execute_on_validator(|v| v.latest_finalized_header())?;
				GLOBAL_FULL_PARACHAIN2_HANDLER_COMPONENT.initialize(handler.into());
				Ok(header.encode())
			},
		},
		ParentchainInitParams::Solochain { id, params } => match id {
			ParentchainId::Teerex => {
				let handler = FullSolochainHandler::init::<WorkerModeProvider>(base_path, params)?;
				let header = handler
					.validator_accessor
					.execute_on_validator(|v| v.latest_finalized_header())?;
				GLOBAL_FULL_SOLOCHAIN_HANDLER_COMPONENT.initialize(handler.into());
				Ok(header.encode())
			},
			ParentchainId::Secondary => {
				let handler = FullSolochainHandler2::init::<WorkerModeProvider>(base_path, params)?;
				let header = handler
					.validator_accessor
					.execute_on_validator(|v| v.latest_finalized_header())?;
				GLOBAL_FULL_SOLOCHAIN2_HANDLER_COMPONENT.initialize(handler.into());
				Ok(header.encode())
			},
		},
	}
}
