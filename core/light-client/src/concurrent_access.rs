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
	LightClientState, Validator,
};
use finality_grandpa::BlockNumberOps;
use itp_sgx_io::SealedIO;
use lazy_static::lazy_static;
use sp_runtime::traits::{Block as BlockT, NumberFor};
use std::marker::PhantomData;

lazy_static! {
	// As long as we have a file backend, we use this 'dummy' lock,
	// which guards against concurrent read/write access.
	pub static ref VALIDATOR_LOCK: RwLock<()> = Default::default();
}

/// Retrieve an exclusive lock on a validator for either read or write access.
///
/// In order to hide the whole locks mechanics, we provide an interface that allows executing
/// either a mutating, or a non-mutating function on the validator.
/// The reason we have this additional wrapper around `SealedIO`, is that we need
/// to guard against concurrent access by using RWLocks (which `SealedIO` does not do).
pub trait ValidatorAccess<PB>
where
	PB: BlockT,
	NumberFor<PB>: BlockNumberOps,
{
	type ValidatorType: Validator<PB> + LightClientState<PB>;

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
#[derive(Clone, Debug)]
pub struct GlobalValidatorAccessor<ValidatorT, PB, Seal>
where
	ValidatorT: Validator<PB> + LightClientState<PB>,
	Seal: SealedIO<Error = Error, Unsealed = ValidatorT>,
	PB: BlockT,
	NumberFor<PB>: BlockNumberOps,
{
	_phantom: PhantomData<(Seal, ValidatorT, PB)>,
}

impl<ValidatorT, PB, Seal> Default for GlobalValidatorAccessor<ValidatorT, PB, Seal>
where
	ValidatorT: Validator<PB> + LightClientState<PB>,
	Seal: SealedIO<Error = Error, Unsealed = ValidatorT>,
	PB: BlockT,
	NumberFor<PB>: BlockNumberOps,
{
	fn default() -> Self {
		GlobalValidatorAccessor { _phantom: Default::default() }
	}
}

impl<ValidatorT, PB, Seal> GlobalValidatorAccessor<ValidatorT, PB, Seal>
where
	ValidatorT: Validator<PB> + LightClientState<PB>,
	Seal: SealedIO<Error = Error, Unsealed = ValidatorT>,
	PB: BlockT,
	NumberFor<PB>: BlockNumberOps,
{
	pub fn new() -> Self {
		GlobalValidatorAccessor { _phantom: Default::default() }
	}
}

impl<ValidatorT, PB, Seal> ValidatorAccess<PB> for GlobalValidatorAccessor<ValidatorT, PB, Seal>
where
	ValidatorT: Validator<PB> + LightClientState<PB>,
	Seal: SealedIO<Error = Error, Unsealed = ValidatorT>,
	PB: BlockT,
	NumberFor<PB>: BlockNumberOps,
{
	type ValidatorType = ValidatorT;

	fn execute_on_validator<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::ValidatorType) -> Result<R>,
	{
		let _read_lock = VALIDATOR_LOCK.read().map_err(|_| Error::PoisonedLock)?;
		let validator = Seal::unseal()?;
		getter_function(&validator)
	}

	fn execute_mut_on_validator<F, R>(&self, mutating_function: F) -> Result<R>
	where
		F: FnOnce(&mut Self::ValidatorType) -> Result<R>,
	{
		let _write_lock = VALIDATOR_LOCK.write().map_err(|_| Error::PoisonedLock)?;
		let mut validator = Seal::unseal()?;
		let result = mutating_function(&mut validator);
		Seal::seal(validator)?;
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mocks::{validator_mock::ValidatorMock, validator_mock_seal::ValidatorMockSeal};
	use itp_types::Block;

	type TestAccessor = GlobalValidatorAccessor<ValidatorMock, Block, ValidatorMockSeal>;

	#[test]
	fn execute_with_and_without_mut_in_single_thread_works() {
		let accessor = TestAccessor::default();
		let _read_result = accessor.execute_on_validator(|_v| Ok(())).unwrap();
		let _write_result = accessor.execute_mut_on_validator(|_v| Ok(())).unwrap();
	}
}
