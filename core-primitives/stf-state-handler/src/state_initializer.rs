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

use crate::error::Result;
use core::marker::PhantomData;
use itp_sgx_crypto::{ed25519_derivation::DeriveEd25519, key_repository::AccessKey};
use itp_stf_interface::InitState;
use itp_types::AccountId;
use sp_core::Pair;
use std::sync::Arc;

/// Create and initialize a new state instance.
pub trait InitializeState {
	type StateType;

	fn initialize(&self) -> Result<Self::StateType>;
}

pub struct StateInitializer<State, Stf, ShieldingKeyRepository> {
	shielding_key_repository: Arc<ShieldingKeyRepository>,
	_phantom: PhantomData<(State, Stf)>,
}

impl<State, Stf, ShieldingKeyRepository> StateInitializer<State, Stf, ShieldingKeyRepository>
where
	Stf: InitState<State, AccountId>,
	ShieldingKeyRepository: AccessKey,
	ShieldingKeyRepository::KeyType: DeriveEd25519,
{
	pub fn new(shielding_key_repository: Arc<ShieldingKeyRepository>) -> Self {
		Self { shielding_key_repository, _phantom: Default::default() }
	}
}

impl<State, Stf, ShieldingKeyRepository> InitializeState
	for StateInitializer<State, Stf, ShieldingKeyRepository>
where
	Stf: InitState<State, AccountId>,
	ShieldingKeyRepository: AccessKey,
	ShieldingKeyRepository::KeyType: DeriveEd25519,
{
	type StateType = State;

	fn initialize(&self) -> Result<Self::StateType> {
		// This implementation basically exists because it is non-trivial to initialize the state with
		// an enclave account that is derived from the shielding key.
		let enclave_account = self.shielding_key_repository.retrieve_key()?.derive_ed25519()?;
		Ok(Stf::init_state(enclave_account.public().into()))
	}
}
