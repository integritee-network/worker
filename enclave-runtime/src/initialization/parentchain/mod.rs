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

mod common;
mod solochain;

use sp_runtime::traits::Header as HeaderTrait;

use crate::initialization::global_components::GLOBAL_SOLOCHAIN_HANDLER_COMPONENT;

pub(crate) fn init_parentchain_components<WorkerModeProvider: ProvideWorkerMode>(
	params: LightClientInitParams<Header>,
) -> EnclaveResult<Header> {
	let latest_header = match LightClientInitParams {
		LightClientInitParams::Grandpa(..) => SolochainHandler::init(params),
		LightClientInitParams::Parachain(..) => ParachainHandler::init(params),
	}?;

	Ok(latest_header)
}
