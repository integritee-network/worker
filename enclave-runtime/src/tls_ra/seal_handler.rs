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
//! shielding key, signing key and state.

use crate::error::{Error as EnclaveError, Result as EnclaveResult};
use codec::{Decode, Encode};
use ita_stf::{State as StfState, StateType as StfStateType};
use itp_sgx_crypto::{Aes, AesSeal, Error as CryptoError};
use itp_sgx_io::SealedIO;
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::ShardIdentifier;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::{marker::PhantomData, sync::Arc, vec::Vec};

pub trait SealedIOForShieldingKey = SealedIO<Unsealed = Rsa3072KeyPair, Error = CryptoError>;
pub trait SealedIOForSigningKey = SealedIO<Unsealed = Aes, Error = CryptoError>;

/// Handles the sealing and unsealing of the shielding key, signing key and the state.
#[derive(Default)]
pub struct SealHandler<ShieldingKeyHandler, SigningKeyHandler, StateHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
	// Constraint StateT = StfState currently necessary because SgxExternalities Encode/Decode does not work.
	// See https://github.com/integritee-network/sgx-runtime/issues/46.
	StateHandler: HandleState<StateT = StfState>,
{
	state_handler: Arc<StateHandler>,
	_phantom_shield: PhantomData<ShieldingKeyHandler>,
	_phantom_sign: PhantomData<SigningKeyHandler>,
}

impl<ShieldingKeyHandler, SigningKeyHandler, StateHandler>
	SealHandler<ShieldingKeyHandler, SigningKeyHandler, StateHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
	StateHandler: HandleState<StateT = StfState>,
{
	pub fn new(state_handler: Arc<StateHandler>) -> Self {
		Self {
			state_handler,
			_phantom_shield: Default::default(),
			_phantom_sign: Default::default(),
		}
	}
}
pub trait SealStateAndKeys {
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_signing_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_state(&self, bytes: &[u8], shard: &ShardIdentifier) -> EnclaveResult<()>;
}

pub trait UnsealStateAndKeys {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_state(&self, state: &ShardIdentifier) -> EnclaveResult<Vec<u8>>;
}

impl<ShieldingKeyHandler, SigningKeyHandler, StateHandler> SealStateAndKeys
	for SealHandler<ShieldingKeyHandler, SigningKeyHandler, StateHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
	StateHandler: HandleState<StateT = StfState>,
{
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()> {
		let key: Rsa3072KeyPair = serde_json::from_slice(bytes).map_err(|e| {
			error!("    [Enclave] Received Invalid RSA key");
			EnclaveError::Other(e.into())
		})?;
		ShieldingKeyHandler::seal(key)?;
		Ok(())
	}

	fn seal_signing_key(&self, mut bytes: &[u8]) -> EnclaveResult<()> {
		let aes = Aes::decode(&mut bytes)?;
		AesSeal::seal(Aes::new(aes.key, aes.init_vec))?;
		Ok(())
	}

	fn seal_state(&self, mut bytes: &[u8], shard: &ShardIdentifier) -> EnclaveResult<()> {
		let state = StfStateType::decode(&mut bytes)?;
		let state_with_empty_diff = StfState { state, state_diff: Default::default() };
		let (state_lock, _) = self.state_handler.load_for_mutation(shard)?;

		self.state_handler.write(state_with_empty_diff, state_lock, shard)?;
		Ok(())
	}
}

impl<ShieldingKeyHandler, SigningKeyHandler, StateHandler> UnsealStateAndKeys
	for SealHandler<ShieldingKeyHandler, SigningKeyHandler, StateHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
	StateHandler: HandleState<StateT = StfState>,
{
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		let shielding_key = ShieldingKeyHandler::unseal()?;
		serde_json::to_vec(&shielding_key).map_err(|e| EnclaveError::Other(e.into()))
	}

	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(AesSeal::unseal()?.encode())
	}

	fn unseal_state(&self, shard: &ShardIdentifier) -> EnclaveResult<Vec<u8>> {
		let state = self.state_handler.load_initialized(shard)?;
		Ok(state.state.encode())
	}
}

#[cfg(feature = "test")]
pub mod test {
	use super::*;
	use itp_sgx_crypto::mocks::{AesSealMock, Rsa3072SealMock};
	use itp_test::mock::handle_state_mock::HandleStateMock;
	use sgx_externalities::SgxExternalitiesTrait;

	type SealHandlerMock = SealHandler<Rsa3072SealMock, AesSealMock, HandleStateMock>;

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

	pub fn seal_signing_key_works() {
		let seal_handler = SealHandlerMock::default();
		let key_pair_in_bytes = Aes::default().encode();

		let result = seal_handler.seal_signing_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_signing_key_fails_for_invalid_key() {
		let seal_handler = SealHandlerMock::default();

		let result = seal_handler.seal_signing_key(&[1, 2, 3]);

		assert!(result.is_err());
	}

	pub fn unseal_seal_signing_key_works() {
		let seal_handler = SealHandlerMock::default();
		let key_pair_in_bytes = seal_handler.unseal_signing_key().unwrap();

		let result = seal_handler.seal_signing_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_state_works() {
		let seal_handler = SealHandlerMock::default();
		let state = <HandleStateMock as HandleState>::StateT::default();
		let shard = ShardIdentifier::default();

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
		// Fill our mock state:
		let (lock, mut state) = seal_handler.state_handler.load_for_mutation(&shard).unwrap();
		let (key, value) = ("my_key", "my_value");
		state.insert(key.encode(), value.encode());
		seal_handler.state_handler.write(state, lock, &shard).unwrap();

		let state_in_bytes = seal_handler.unseal_state(&shard).unwrap();

		let result = seal_handler.seal_state(&state_in_bytes, &shard);

		assert!(result.is_ok());
	}
}
