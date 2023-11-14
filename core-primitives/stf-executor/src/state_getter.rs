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
use codec::Decode;
use core::marker::PhantomData;
use itp_sgx_externalities::SgxExternalities;
use itp_stf_interface::StateGetterInterface;
use itp_stf_primitives::traits::GetterAuthorization;
use log::*;
use std::vec::Vec;

/// Abstraction for accessing state with a getter.
pub trait GetState<StateType, G: PartialEq + Decode + GetterAuthorization> {
	/// Executes a trusted getter on a state and return its value, if available.
	///
	/// Also verifies the signature of the trusted getter and returns an error
	/// if it's invalid.
	fn get_state(getter: G, state: &mut StateType) -> Result<Option<Vec<u8>>>;
}

pub struct StfStateGetter<Stf> {
	_phantom: PhantomData<Stf>,
}

impl<Stf, G> GetState<SgxExternalities, G> for StfStateGetter<Stf>
where
	Stf: StateGetterInterface<G, SgxExternalities>,
	G: PartialEq + Decode + GetterAuthorization,
{
	fn get_state(getter: G, state: &mut SgxExternalities) -> Result<Option<Vec<u8>>> {
		if !getter.is_authorized() {
			error!("getter authorization failed");
			return Err(Error::GetterIsNotAuthorized)
		}
		debug!("getter authorized. calling into STF to get state");
		Ok(Stf::execute_getter(state, getter))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use core::assert_matches::assert_matches;

	use itp_test::mock::stf_mock::{
		GetterMock, StfMock, TrustedGetterMock, TrustedGetterSignedMock,
	};

	type TestStateGetter = StfStateGetter<StfMock>;

	#[test]
	fn upon_false_signature_get_stf_state_errs() {
		let getter =
			TrustedGetterSignedMock { getter: TrustedGetterMock::some_value, signature: false };
		let mut state = SgxExternalities::default();

		assert_matches!(
			TestStateGetter::get_state(GetterMock::trusted(getter), &mut state),
			Err(Error::GetterIsNotAuthorized)
		);
	}

	#[test]
	fn state_getter_is_executed_if_signature_is_correct() {
		let getter =
			TrustedGetterSignedMock { getter: TrustedGetterMock::some_value, signature: true };
		let mut state = SgxExternalities::default();
		assert!(TestStateGetter::get_state(GetterMock::trusted(getter), &mut state).is_ok());
	}
}
