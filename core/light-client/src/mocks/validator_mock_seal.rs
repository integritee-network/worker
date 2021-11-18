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

use crate::{error::Error, mocks::validator_mock::ValidatorMock};
use itp_sgx_io::SealedIO;

/// A seal that return a mock validator.
#[derive(Clone)]
pub struct ValidatorMockSeal;

impl SealedIO for ValidatorMockSeal {
	type Error = Error;
	type Unsealed = ValidatorMock;

	fn unseal() -> Result<Self::Unsealed, Self::Error> {
		Ok(ValidatorMock)
	}

	fn seal(_unsealed: Self::Unsealed) -> Result<(), Self::Error> {
		Ok(())
	}
}
