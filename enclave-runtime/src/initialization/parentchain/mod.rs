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

use crate::error::Result;
use codec::Decode;
use itc_parentchain::primitives::ParentchainInitParams;
use itp_settings::worker_mode::ProvideWorkerMode;
use parachain::FullParachainHandler;
use solochain::FullSolochainHandler;
use std::{path::PathBuf, vec::Vec};

mod common;
pub mod parachain;
pub mod solochain;

pub(crate) fn init_parentchain_components<WorkerModeProvider: ProvideWorkerMode>(
	base_path: PathBuf,
	encoded_params: Vec<u8>,
) -> Result<Vec<u8>> {
	match ParentchainInitParams::decode(&mut encoded_params.as_slice())? {
		ParentchainInitParams::Parachain { params } =>
			FullParachainHandler::init::<WorkerModeProvider>(base_path, params),
		ParentchainInitParams::Solochain { params } =>
			FullSolochainHandler::init::<WorkerModeProvider>(base_path, params),
	}
}
