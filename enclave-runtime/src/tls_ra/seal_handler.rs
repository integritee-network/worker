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

//! Abstraction of the reading (unseal) and storing (seal) part of the
//! shielding key, state key and state.

use crate::error::{Error as EnclaveError, Result as EnclaveResult};
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType};
use itp_sgx_crypto::{
	key_repository::{AccessKey, MutateKey},
	Aes,
};
use itp_sgx_externalities::SgxExternalitiesTrait;
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::ShardIdentifier;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::{sync::Arc, vec::Vec};

/// Handles the sealing and unsealing of the shielding key, state key and the state.
#[derive(Default)]
pub struct SealHandler<ShieldingKeyRepository, StateKeyRepository, StateHandler>
where
	ShieldingKeyRepository: AccessKey<KeyType = Rsa3072KeyPair> + MutateKey<Rsa3072KeyPair>,
	StateKeyRepository: AccessKey<KeyType = Aes> + MutateKey<Aes>,
	// Constraint StateT = StfState currently necessary because SgxExternalities Encode/Decode does not work.
	// See https://github.com/integritee-network/sgx-runtime/issues/46.
	StateHandler: HandleState<StateT = StfState>,
{
	state_handler: Arc<StateHandler>,
	state_key_repository: Arc<StateKeyRepository>,
	shielding_key_repository: Arc<ShieldingKeyRepository>,
}

impl<ShieldingKeyRepository, StateKeyRepository, StateHandler>
	SealHandler<ShieldingKeyRepository, StateKeyRepository, StateHandler>
where
	ShieldingKeyRepository: AccessKey<KeyType = Rsa3072KeyPair> + MutateKey<Rsa3072KeyPair>,
	StateKeyRepository: AccessKey<KeyType = Aes> + MutateKey<Aes>,
	StateHandler: HandleState<StateT = StfState>,
{
	pub fn new(
		state_handler: Arc<StateHandler>,
		state_key_repository: Arc<StateKeyRepository>,
		shielding_key_repository: Arc<ShieldingKeyRepository>,
	) -> Self {
		Self { state_handler, state_key_repository, shielding_key_repository }
	}
}

pub trait SealStateAndKeys {
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_state_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_state(&self, bytes: &[u8], shard: &ShardIdentifier) -> EnclaveResult<()>;
	fn seal_new_empty_state(&self, shard: &ShardIdentifier) -> EnclaveResult<()>;
}

pub trait UnsealStateAndKeys {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_state_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_state(&self, shard: &ShardIdentifier) -> EnclaveResult<Vec<u8>>;
}

impl<ShieldingKeyRepository, StateKeyRepository, StateHandler> SealStateAndKeys
	for SealHandler<ShieldingKeyRepository, StateKeyRepository, StateHandler>
where
	ShieldingKeyRepository: AccessKey<KeyType = Rsa3072KeyPair> + MutateKey<Rsa3072KeyPair>,
	StateKeyRepository: AccessKey<KeyType = Aes> + MutateKey<Aes>,
	StateHandler: HandleState<StateT = StfState>,
{
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		let key: Rsa3072KeyPair = serde_json::from_slice(bytes).map_err(|e| {
			error!("    [Enclave] Received Invalid RSA key");
			EnclaveError::Other(e.into())
		})?;
		self.shielding_key_repository.update_key(key)?;
		info!("Successfully stored a new shielding key");
		Ok(())
	}

	fn seal_state_key(&self, mut bytes: &[u8]) -> EnclaveResult<()> {
		let aes = Aes::decode(&mut bytes)?;
		self.state_key_repository.update_key(aes)?;
		info!("Successfully stored a new state key");
		Ok(())
	}

	fn seal_state(&self, mut bytes: &[u8], shard: &ShardIdentifier) -> EnclaveResult<()> {
		let state = StfStateType::decode(&mut bytes)?;
		let state_with_empty_diff = StfState::new(state);

		self.state_handler.reset(state_with_empty_diff, shard)?;
		info!("Successfully updated shard {:?} with provisioned state", shard);
		Ok(())
	}

	/// Seal an empty, newly initialized state.
	///
	/// Requires the shielding key to be sealed and updated before calling this.
	///
	/// Call this function in case we don't provision the state itself, only the shielding key.
	/// Since the enclave signing account is derived from the shielding key, we need to
	/// newly initialize the state with the updated shielding key.
	fn seal_new_empty_state(&self, shard: &ShardIdentifier) -> EnclaveResult<()> {
		self.state_handler.initialize_shard(*shard)?;
		info!("Successfully reset state with new enclave account, for shard {:?}", shard);
		Ok(())
	}
}

impl<ShieldingKeyRepository, StateKeyRepository, StateHandler> UnsealStateAndKeys
	for SealHandler<ShieldingKeyRepository, StateKeyRepository, StateHandler>
where
	ShieldingKeyRepository: AccessKey<KeyType = Rsa3072KeyPair> + MutateKey<Rsa3072KeyPair>,
	StateKeyRepository: AccessKey<KeyType = Aes> + MutateKey<Aes>,
	StateHandler: HandleState<StateT = StfState>,
{
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		let shielding_key = self
			.shielding_key_repository
			.retrieve_key()
			.map_err(|e| EnclaveError::Other(format!("{:?}", e).into()))?;
		serde_json::to_vec(&shielding_key).map_err(|e| EnclaveError::Other(e.into()))
	}

	fn unseal_state_key(&self) -> EnclaveResult<Vec<u8>> {
		self.state_key_repository
			.retrieve_key()
			.map(|k| k.encode())
			.map_err(|e| EnclaveError::Other(format!("{:?}", e).into()))
	}

	fn unseal_state(&self, shard: &ShardIdentifier) -> EnclaveResult<Vec<u8>> {
		Ok(self.state_handler.execute_on_current(shard, |state, _| state.state.encode())?)
	}
}

#[cfg(feature = "test")]
pub mod test {
	use super::*;
	use itp_sgx_crypto::mocks::KeyRepositoryMock;
	use itp_test::mock::handle_state_mock::HandleStateMock;

	type StateKeyRepositoryMock = KeyRepositoryMock<Aes>;
	type ShieldingKeyRepositoryMock = KeyRepositoryMock<Rsa3072KeyPair>;

	type SealHandlerMock =
		SealHandler<ShieldingKeyRepositoryMock, StateKeyRepositoryMock, HandleStateMock>;

	pub fn seal_shielding_key_works() {
		let seal_handler = SealHandlerMock::default();
		let key_pair_in_bytes = serde_json::to_vec(&Rsa3072KeyPair::default()).unwrap();

		let result = seal_handler.seal_shielding_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_shielding_key_fails_for_invalid_key() {
		let seal_handler = SealHandlerMock::default();

		let result = seal_handler.seal_shielding_key(&[1, 2, 3]);

		assert!(result.is_err());
	}

	pub fn unseal_seal_shielding_key_works() {
		let seal_handler = SealHandlerMock::default();

		let key_pair_in_bytes = seal_handler.unseal_shielding_key().unwrap();

		let result = seal_handler.seal_shielding_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_state_key_works() {
		let seal_handler = SealHandlerMock::default();
		let key_pair_in_bytes = Aes::default().encode();

		let result = seal_handler.seal_state_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_state_key_fails_for_invalid_key() {
		let seal_handler = SealHandlerMock::default();

		let result = seal_handler.seal_state_key(&[1, 2, 3]);

		assert!(result.is_err());
	}

	pub fn unseal_seal_state_key_works() {
		let seal_handler = SealHandlerMock::default();
		let key_pair_in_bytes = seal_handler.unseal_state_key().unwrap();

		let result = seal_handler.seal_state_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_state_works() {
		let seal_handler = SealHandlerMock::default();
		let state = <HandleStateMock as HandleState>::StateT::default();
		let shard = ShardIdentifier::default();
		let _init_hash = seal_handler.state_handler.initialize_shard(shard).unwrap();

		let result = seal_handler.seal_state(&state.encode(), &shard);

		assert!(result.is_ok());
	}

	pub fn seal_state_fails_for_invalid_state() {
		let seal_handler = SealHandlerMock::default();
		let shard = ShardIdentifier::default();

		let result = seal_handler.seal_state(&[1, 0, 3], &shard);

		assert!(result.is_err());
	}

	pub fn unseal_seal_state_works() {
		let seal_handler = SealHandlerMock::default();
		let shard = ShardIdentifier::default();
		seal_handler.state_handler.initialize_shard(shard).unwrap();
		// Fill our mock state:
		let (lock, mut state) = seal_handler.state_handler.load_for_mutation(&shard).unwrap();
		let (key, value) = ("my_key", "my_value");
		state.insert(key.encode(), value.encode());
		seal_handler.state_handler.write_after_mutation(state, lock, &shard).unwrap();

		let state_in_bytes = seal_handler.unseal_state(&shard).unwrap();

		let result = seal_handler.seal_state(&state_in_bytes, &shard);

		assert!(result.is_ok());
	}
}
