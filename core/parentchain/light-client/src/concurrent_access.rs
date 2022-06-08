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
	ExtrinsicSender as ExtrinsicSenderTrait, LightClientState, LightValidationState,
	Validator as ValidatorTrait,
};
use finality_grandpa::BlockNumberOps;
use itp_ocall_api::EnclaveOnChainOCallApi;
use itp_sgx_io::StaticSealedIO;
use sp_runtime::traits::{Block as ParentchainBlockTrait, NumberFor};
use std::marker::PhantomData;

/// Retrieve an exclusive lock on a validator for either read or write access.
///
/// In order to hide the whole locks mechanics, we provide an interface that allows executing
/// either a mutating, or a non-mutating function on the validator.
/// The reason we have this additional wrapper around `SealedIO`, is that we need
/// to guard against concurrent access by using RWLocks (which `SealedIO` does not do).
pub trait ValidatorAccess<ParentchainBlock, OCallApi>
where
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
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
pub struct ValidatorAccessor<Validator, ParentchainBlock, Seal, OCallApi>
where
	Validator: ValidatorTrait<ParentchainBlock>
		+ LightClientState<ParentchainBlock>
		+ ExtrinsicSenderTrait,
	Seal: StaticSealedIO<Error = Error, Unsealed = LightValidationState<ParentchainBlock>>,
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	light_validation: RwLock<Validator>,
	_phantom: PhantomData<(Seal, Validator, ParentchainBlock, OCallApi)>,
}

impl<Validator, ParentchainBlock, Seal, OCallApi>
	ValidatorAccessor<Validator, ParentchainBlock, Seal, OCallApi>
where
	Validator: ValidatorTrait<ParentchainBlock>
		+ LightClientState<ParentchainBlock>
		+ ExtrinsicSenderTrait,
	Seal: StaticSealedIO<Error = Error, Unsealed = LightValidationState<ParentchainBlock>>,
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	pub fn new(validator: Validator) -> Self {
		ValidatorAccessor { light_validation: RwLock::new(validator), _phantom: Default::default() }
	}
}

impl<Validator, ParentchainBlock, Seal, OCallApi> ValidatorAccess<ParentchainBlock, OCallApi>
	for ValidatorAccessor<Validator, ParentchainBlock, Seal, OCallApi>
where
	Validator: ValidatorTrait<ParentchainBlock>
		+ LightClientState<ParentchainBlock>
		+ ExtrinsicSenderTrait,
	Seal: StaticSealedIO<Error = Error, Unsealed = LightValidationState<ParentchainBlock>>,
	ParentchainBlock: ParentchainBlockTrait,
	NumberFor<ParentchainBlock>: BlockNumberOps,
	OCallApi: EnclaveOnChainOCallApi,
{
	type ValidatorType = Validator;

	fn execute_on_validator<F, R>(&self, getter_function: F) -> Result<R>
	where
		F: FnOnce(&Self::ValidatorType) -> Result<R>,
	{
		let mut light_validation_lock =
			self.light_validation.write().map_err(|_| Error::PoisonedLock)?;
		let state = Seal::unseal_from_static_file()?;
		light_validation_lock.set_state(state);
		getter_function(&light_validation_lock)
	}

	fn execute_mut_on_validator<F, R>(&self, mutating_function: F) -> Result<R>
	where
		F: FnOnce(&mut Self::ValidatorType) -> Result<R>,
	{
		let mut light_validation_lock =
			self.light_validation.write().map_err(|_| Error::PoisonedLock)?;
		let state = Seal::unseal_from_static_file()?;
		light_validation_lock.set_state(state);
		let result = mutating_function(&mut light_validation_lock);
		Seal::seal_to_static_file(light_validation_lock.get_state())?;
		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::mocks::{
		validator_mock::ValidatorMock, validator_mock_seal::LightValidationStateSealMock,
	};
	use itp_test::mock::onchain_mock::OnchainMock;
	use itp_types::Block;

	type TestAccessor =
		ValidatorAccessor<ValidatorMock, Block, LightValidationStateSealMock, OnchainMock>;

	#[test]
	fn execute_with_and_without_mut_in_single_thread_works() {
		let validator_mock = ValidatorMock::default();
		let accessor = TestAccessor::new(validator_mock);

		let _read_result = accessor.execute_on_validator(|_v| Ok(())).unwrap();
		let _write_result = accessor.execute_mut_on_validator(|_v| Ok(())).unwrap();
	}
}
