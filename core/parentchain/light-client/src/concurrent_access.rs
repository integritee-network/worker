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

//! Concurrent access mechanisms that ensure mutually exclusive read/write access
//! to the light-client (validator) by employing RwLocks under the hood.

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::{
	error::{Error, Result},
	ExtrinsicSender as ExtrinsicSenderTrait, LightClientSealing, LightClientState,
	LightValidationState, Validator as ValidatorTrait,
};
use finality_grandpa::BlockNumberOps;
use sp_runtime::traits::{Block as ParentchainBlockTrait, NumberFor};
use std::marker::PhantomData;

/// Retrieve an exclusive lock on a validator for either read or write access.
///
/// In order to hide the whole locks mechanics, we provide an interface that allows executing
/// either a mutating, or a non-mutating function on the validator.
/// The reason we have this additional wrapper around `SealedIO`, is that we need
/// to guard against concurrent access by using RWLocks (which `SealedIO` does not do).
pub trait ValidatorAccess<ParentchainBlock>
where
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
{
	type ValidatorType: ValidatorTrait<ParentchainBlock>
		+ LightClientState<ParentchainBlock>
		+ ExtrinsicSenderTrait;

	/// Execute a non-mutating function on the validator.
	fn execute_on_validator<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::ValidatorType) -> Result<R>;

	/// Execute a mutating function on the validator.
	fn execute_mut_on_validator<F, R>(&self, mutating_function: F) -> Result<R>
	where
		F: FnOnce(&mut Self::ValidatorType) -> Result<R>;
}

/// Implementation of a validator access based on a global lock and corresponding file.
#[derive(Debug)]
pub struct ValidatorAccessor<Validator, ParentchainBlock, LightClientSeal> {
	seal: LightClientSeal,
	light_validation: RwLock<Validator>,
	_phantom: PhantomData<(LightClientSeal, Validator, ParentchainBlock)>,
}

impl<Validator, ParentchainBlock, LightClientSeal>
	ValidatorAccessor<Validator, ParentchainBlock, LightClientSeal>
{
	pub fn new(validator: Validator, seal: LightClientSeal) -> Self {
		ValidatorAccessor {
			light_validation: RwLock::new(validator),
			seal,
			_phantom: Default::default(),
		}
	}
}

impl<Validator, ParentchainBlock, Seal> ValidatorAccess<ParentchainBlock>
	for ValidatorAccessor<Validator, ParentchainBlock, Seal>
where
	Validator: ValidatorTrait<ParentchainBlock>
		+ LightClientState<ParentchainBlock>
		+ ExtrinsicSenderTrait,
	Seal: LightClientSealing<LightValidationState<ParentchainBlock>>,
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
{
	type ValidatorType = Validator;

	fn execute_on_validator<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::ValidatorType) -> Result<R>,
	{
		let light_validation_lock =
			self.light_validation.write().map_err(|_| Error::PoisonedLock)?;
		getter_function(&light_validation_lock)
	}

	fn execute_mut_on_validator<F, R>(&self, mutating_function: F) -> Result<R>
	where
		F: FnOnce(&mut Self::ValidatorType) -> Result<R>,
	{
		let mut light_validation_lock =
			self.light_validation.write().map_err(|_| Error::PoisonedLock)?;
		let result = mutating_function(&mut light_validation_lock);
		self.seal.seal(light_validation_lock.get_state())?;
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mocks::{
		validator_mock::ValidatorMock, validator_mock_seal::LightValidationStateSealMock,
	};
	use itp_types::Block;

	type TestAccessor = ValidatorAccessor<ValidatorMock, Block, LightValidationStateSealMock>;

	#[test]
	fn execute_with_and_without_mut_in_single_thread_works() {
		let validator_mock = ValidatorMock::default();
		let seal = LightValidationStateSealMock::new();
		let accessor = TestAccessor::new(validator_mock, seal);

		let _read_result = accessor.execute_on_validator(|_v| Ok(())).unwrap();
		let _write_result = accessor.execute_mut_on_validator(|_v| Ok(())).unwrap();
	}
}
