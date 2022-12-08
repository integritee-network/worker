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

//! Getter executor uses the state observer to get the most recent state and runs the getter on it.
//! The getter is verified (signature verfification) inside the `GetState` implementation.

use crate::{
	error::{Error, Result},
	state_getter::GetState,
};
use codec::Decode;
use ita_stf::Getter;
use itp_stf_state_observer::traits::ObserveState;
use itp_types::ShardIdentifier;
use log::*;
use std::{format, marker::PhantomData, sync::Arc, time::Instant, vec::Vec};

/// Trait to execute a getter for a specific shard.
pub trait ExecuteGetter {
	fn execute_getter(
		&self,
		shard: &ShardIdentifier,
		encoded_signed_getter: Vec<u8>,
	) -> Result<Option<Vec<u8>>>;
}

pub struct GetterExecutor<StateObserver, StateGetter> {
	state_observer: Arc<StateObserver>,
	_phantom: PhantomData<StateGetter>,
}

impl<StateObserver, StateGetter> GetterExecutor<StateObserver, StateGetter> {
	pub fn new(state_observer: Arc<StateObserver>) -> Self {
		Self { state_observer, _phantom: Default::default() }
	}
}

impl<StateObserver, StateGetter> ExecuteGetter for GetterExecutor<StateObserver, StateGetter>
where
	StateObserver: ObserveState,
	StateGetter: GetState<StateObserver::StateType>,
{
	fn execute_getter(
		&self,
		shard: &ShardIdentifier,
		encoded_signed_getter: Vec<u8>,
	) -> Result<Option<Vec<u8>>> {
		let getter: Getter = Decode::decode(&mut encoded_signed_getter.as_slice())?;

		trace!("Successfully decoded trusted getter");
		if let Getter::trusted(trusted_getter_signed) = getter {
			let getter_timer_start = Instant::now();
			let state_result = self.state_observer.observe_state(shard, |state| {
				StateGetter::get_state(&trusted_getter_signed, state)
			})??;

			debug!("Getter executed in {} ms", getter_timer_start.elapsed().as_millis());

			Ok(state_result)
		} else {
			Err(Error::Other(format!("Unsupported getter type: {:?}", getter).into()))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use codec::{Decode, Encode};
	use ita_stf::{PublicGetter, TrustedGetter, TrustedGetterSigned};
	use itp_stf_primitives::types::AccountId;
	use itp_stf_state_observer::mock::ObserveStateMock;
	use sp_core::ed25519::Signature;
	use sp_runtime::MultiSignature;

	type TestState = u64;
	type TestStateObserver = ObserveStateMock<TestState>;

	struct TestStateGetter;
	impl GetState<TestState> for TestStateGetter {
		fn get_state(
			_getter: &TrustedGetterSigned,
			state: &mut TestState,
		) -> Result<Option<Vec<u8>>> {
			Ok(Some(state.encode()))
		}
	}

	type TestGetterExecutor = GetterExecutor<TestStateObserver, TestStateGetter>;

	#[test]
	fn executing_getters_works() {
		let test_state = 23489u64;
		let state_observer = Arc::new(TestStateObserver::new(test_state));
		let getter_executor = TestGetterExecutor::new(state_observer);
		let getter = Getter::trusted(dummy_trusted_getter());

		let state_result = getter_executor
			.execute_getter(&ShardIdentifier::default(), getter.encode())
			.unwrap()
			.unwrap();
		let decoded_state: TestState = Decode::decode(&mut state_result.as_slice()).unwrap();
		assert_eq!(decoded_state, test_state);
	}

	#[test]
	fn executing_public_getter_gives_error() {
		// no support for public getters yet.
		let getter = Getter::public(PublicGetter::some_value);

		let test_state = 23489u64;
		let state_observer = Arc::new(TestStateObserver::new(test_state));
		let getter_executor = TestGetterExecutor::new(state_observer);

		assert!(getter_executor
			.execute_getter(&ShardIdentifier::default(), getter.encode())
			.is_err());
	}

	fn dummy_trusted_getter() -> TrustedGetterSigned {
		TrustedGetterSigned::new(
			TrustedGetter::nonce(AccountId::new([0u8; 32])),
			MultiSignature::Ed25519(Signature::from_raw([0u8; 64])),
		)
	}
}
