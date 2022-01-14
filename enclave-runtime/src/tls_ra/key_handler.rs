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

use crate::error::{Error as EnclaveError, Result as EnclaveResult};
use codec::{Decode, Encode};
use itp_sgx_crypto::{Aes, AesSeal, Error as CryptoError};
use itp_sgx_io::SealedIO;
use log::*;
use sgx_crypto_helper::rsa3072::Rsa3072KeyPair;
use std::{marker::PhantomData, vec::Vec};

pub trait SealedIOForShieldingKey = SealedIO<Unsealed = Rsa3072KeyPair, Error = CryptoError>;
pub trait SealedIOForSigningKey = SealedIO<Unsealed = Aes, Error = CryptoError>;

#[derive(Default)]
pub struct KeyHandler<ShieldingKeyHandler, SigningKeyHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
{
	_phantom_shield: PhantomData<ShieldingKeyHandler>,
	_phantom_sign: PhantomData<SigningKeyHandler>,
}

impl<ShieldingKeyHandler, SigningKeyHandler> KeyHandler<ShieldingKeyHandler, SigningKeyHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
{
	pub fn new() -> Self {
		KeyHandler { _phantom_shield: Default::default(), _phantom_sign: Default::default() }
	}
}
pub trait SealKeys {
	fn seal_shielding_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
	fn seal_signing_key(&self, bytes: &[u8]) -> EnclaveResult<()>;
}

pub trait UnsealKeys {
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>>;
	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>>;
}

impl<ShieldingKeyHandler, SigningKeyHandler> SealKeys
	for KeyHandler<ShieldingKeyHandler, SigningKeyHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
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
}

impl<ShieldingKeyHandler, SigningKeyHandler> UnsealKeys
	for KeyHandler<ShieldingKeyHandler, SigningKeyHandler>
where
	ShieldingKeyHandler: SealedIOForShieldingKey,
	SigningKeyHandler: SealedIOForSigningKey,
{
	fn unseal_shielding_key(&self) -> EnclaveResult<Vec<u8>> {
		let shielding_key = ShieldingKeyHandler::unseal()?;
		serde_json::to_vec(&shielding_key).map_err(|e| EnclaveError::Other(e.into()))
	}

	fn unseal_signing_key(&self) -> EnclaveResult<Vec<u8>> {
		Ok(AesSeal::unseal()?.encode())
	}
}

#[cfg(feature = "test")]
pub mod test {
	use super::*;
	use itp_sgx_crypto::mocks::{AesSealMock, Rsa3072SealMock};

	type KeyHandlerMock = KeyHandler<Rsa3072SealMock, AesSealMock>;

	pub fn seal_shielding_key_works() {
		let key_handler = KeyHandlerMock::default();
		let key_pair_in_bytes = serde_json::to_vec(&Rsa3072KeyPair::default()).unwrap();

		let result = key_handler.seal_shielding_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_shielding_key_fails_for_wrong_key() {
		let key_handler = KeyHandlerMock::default();

		let result = key_handler.seal_shielding_key(&[1, 2, 3]);

		assert!(result.is_err());
	}

	pub fn unseal_seal_shielding_key_works() {
		let key_handler = KeyHandlerMock::default();

		let key_pair_in_bytes = key_handler.unseal_shielding_key().unwrap();

		let result = key_handler.seal_shielding_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_signing_key_works() {
		let key_handler = KeyHandlerMock::default();
		let key_pair_in_bytes = Aes::default().encode();

		let result = key_handler.seal_signing_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}

	pub fn seal_signing_key_fails_for_wrong_key() {
		let key_handler = KeyHandlerMock::default();

		let result = key_handler.seal_signing_key(&[1, 2, 3]);

		assert!(result.is_err());
	}

	pub fn unseal_seal_signing_key_works() {
		let key_handler = KeyHandlerMock::default();
		let key_pair_in_bytes = key_handler.unseal_signing_key().unwrap();

		let result = key_handler.seal_signing_key(&key_pair_in_bytes);

		assert!(result.is_ok());
	}
}
