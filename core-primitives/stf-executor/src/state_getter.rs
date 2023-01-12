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

use crate::error::{Error, Result};
use core::marker::PhantomData;
use ita_stf::Getter;
use itp_sgx_externalities::SgxExternalities;
use itp_stf_interface::StateGetterInterface;
use log::debug;
use std::vec::Vec;

/// Abstraction for accessing state with a getter.
pub trait GetState<StateType> {
	/// Executes a trusted getter on a state and return its value, if available.
	///
	/// Also verifies the signature of the trusted getter and returns an error
	/// if it's invalid.
	fn get_state(getter: Getter, state: &mut StateType) -> Result<Option<Vec<u8>>>;
}

pub struct StfStateGetter<Stf> {
	_phantom: PhantomData<Stf>,
}

impl<Stf> GetState<SgxExternalities> for StfStateGetter<Stf>
where
	Stf: StateGetterInterface<Getter, SgxExternalities>,
{
	fn get_state(getter: Getter, state: &mut SgxExternalities) -> Result<Option<Vec<u8>>> {
		if let Getter::trusted(ref getter) = getter {
			debug!("verifying signature of TrustedGetterSigned");
			// FIXME: Trusted Getter should not be hardcoded. But
			// verify_signature is currently not available as a Trait.
			if !getter.verify_signature() {
				return Err(Error::OperationHasInvalidSignature)
			}
		}

		debug!("calling into STF to get state");
		Ok(Stf::execute_getter(state, getter))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;
	use ita_stf::TrustedGetter;
	use itp_sgx_externalities::SgxExternalitiesDiffType;
	use itp_stf_interface::mocks::StateInterfaceMock;
	use itp_types::AccountId;
	use sp_core::{ed25519, Pair};

	type TestStf = StateInterfaceMock<SgxExternalities, SgxExternalitiesDiffType>;
	type TestStateGetter = StfStateGetter<TestStf>;

	#[test]
	fn upon_false_signature_get_stf_state_errs() {
		let sender = AccountId::from([0; 32]);
		let wrong_signer = ed25519::Pair::from_seed(b"12345678901234567890123456789012");
		let signed_getter = TrustedGetter::free_balance(sender).sign(&wrong_signer.into());
		let mut state = SgxExternalities::default();

		assert_matches!(
			TestStateGetter::get_state(signed_getter.into(), &mut state),
			Err(Error::OperationHasInvalidSignature)
		);
	}

	#[test]
	fn state_getter_is_executed_if_signature_is_correct() {
		let sender = ed25519::Pair::from_seed(b"12345678901234567890123456789012");
		let signed_getter =
			TrustedGetter::free_balance(sender.public().into()).sign(&sender.into());
		let mut state = SgxExternalities::default();
		assert!(TestStateGetter::get_state(signed_getter.into(), &mut state).is_ok());
	}
}
