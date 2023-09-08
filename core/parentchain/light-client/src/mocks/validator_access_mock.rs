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

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	concurrent_access::ValidatorAccess,
	error::{Error, Result},
	mocks::validator_mock::ValidatorMock,
};
use itp_types::{
	parentchain::{IdentifyParentchain, ParentchainId},
	Block,
};

/// Mock for the validator access.
///
/// Does not execute anything, just a stub.
#[derive(Default)]
pub struct ValidatorAccessMock {
	validator: RwLock<ValidatorMock>,
}

impl ValidatorAccess<Block> for ValidatorAccessMock {
	type ValidatorType = ValidatorMock;

	fn execute_on_validator<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::ValidatorType) -> Result<R>,
	{
		let validator_lock = self.validator.read().map_err(|_| Error::PoisonedLock)?;
		getter_function(&validator_lock)
	}

	fn execute_mut_on_validator<F, R>(&self, mutating_function: F) -> Result<R>
	where
		F: FnOnce(&mut Self::ValidatorType) -> Result<R>,
	{
		let mut validator_lock = self.validator.write().map_err(|_| Error::PoisonedLock)?;
		mutating_function(&mut validator_lock)
	}
}

impl IdentifyParentchain for ValidatorAccessMock {
	fn parentchain_id(&self) -> ParentchainId {
		ParentchainId::Integritee
	}
}
