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

use crate::{error::Error, state::RelayState, LightClientSealing, LightValidationState};
use itc_parentchain_test::parentchain_header_builder::ParentchainHeaderBuilder;
use itp_types::Block;

/// A seal that returns a mock validator.
#[derive(Clone)]
pub struct LightValidationStateSealMock;

impl LightClientSealing<LightValidationState<Block>> for LightValidationStateSealMock {
	fn unseal(&self) -> Result<LightValidationState<Block>, Error> {
		Ok(LightValidationState::new(RelayState::new(
			ParentchainHeaderBuilder::default().build(),
			Default::default(),
		)))
	}

	fn seal(&self, _: &LightValidationState<Block>) -> Result<(), Error> {
		Ok(())
	}

	fn exists(&self) -> bool {
		false
	}

	fn path(&self) -> &'static str {
		"/tmp/db"
	}
}
