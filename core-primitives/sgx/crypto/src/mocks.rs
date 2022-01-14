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
	error::{Error, Result},
	Aes,
};
use itp_sgx_io::SealedIO;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;

#[derive(Default)]
pub struct AesSealMock {}

impl SealedIO for AesSealMock {
	type Error = Error;
	type Unsealed = Aes;

	fn unseal() -> Result<Self::Unsealed> {
		Ok(Aes::default())
	}

	fn seal(_unsealed: Self::Unsealed) -> Result<()> {
		Ok(())
	}
}

#[derive(Default)]
pub struct Rsa3072SealMock {}

impl SealedIO for Rsa3072SealMock {
	type Error = Error;
	type Unsealed = Rsa3072KeyPair;

	fn unseal() -> Result<Self::Unsealed> {
		Ok(Rsa3072KeyPair::default())
	}

	fn seal(_unsealed: Self::Unsealed) -> Result<()> {
		Ok(())
	}
}
